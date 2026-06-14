//! Router firewall. The heavy lifting (conntrack, NAT, the nftables VM) is all
//! in the kernel — this applet just enables forwarding and pushes one nftables
//! ruleset in over netlink, modelled on firewall4's defaults:
//!   table inet lwrt
//!     chain input       { policy drop; ct est,rel accept; lo/lan accept; icmp accept }
//!     chain forward     { policy drop; ct est,rel accept; lan->wan accept; +port-fwd }
//!     chain prerouting  { type nat; per-forward DNAT }
//!     chain postrouting { type nat; masquerade }
//! Programmed via the nf_tables batch protocol on NETLINK_NETFILTER.
//!
//! Port forwards come from config as a comma-separated list:
//!   [firewall]
//!   forward = tcp:8080:192.168.1.10:80, udp:5000:192.168.1.20:5000
//! i.e. `<proto>:<wan_dport>:<dest_ip>:<dest_port>`.

use crate::{config::Config, nl, nl::NlBuf};
use std::fs;
use std::net::Ipv4Addr;

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;

// generic nfnetlink batch
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

// nf_tables message types (within the NFTABLES subsystem)
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;

const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u32 = 2;

// hook numbers
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_LOCAL_IN: u32 = 1;
const NF_INET_FORWARD: u32 = 2;
const NF_INET_POST_ROUTING: u32 = 4;

// verdicts
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

// table attrs
const NFTA_TABLE_NAME: u16 = 1;
// chain attrs
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
// rule attrs
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
// data
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
// ct
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFT_CT_STATE: u32 = 0;
// bitwise
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
// cmp
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
// meta
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_IIFNAME: u32 = 11;
const NFT_META_L4PROTO: u32 = 16;
// payload
const NFTA_PAYLOAD_DREG: u16 = 2;
const NFTA_PAYLOAD_BASE: u16 = 1;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
// immediate
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
// nat
const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
const NFT_NAT_DNAT: u32 = 1;

// registers
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_REG_2: u32 = 2;

// ct states
const CT_ESTABLISHED: u32 = 2;
const CT_RELATED: u32 = 4;

// transport protocols
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

const TABLE: &str = "lwrt";

/// One DNAT port-forward: external `dport` on the router is rewritten to
/// `dest_ip:dest_port` for the given transport protocol.
#[derive(Debug, PartialEq)]
struct Forward {
    proto: u8,
    dport: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
}

/// Parse one `proto:wan_dport:dest_ip:dest_port` spec.
fn parse_forward(spec: &str) -> Option<Forward> {
    let mut it = spec.trim().split(':');
    let proto = match it.next()?.trim().to_ascii_lowercase().as_str() {
        "tcp" => IPPROTO_TCP,
        "udp" => IPPROTO_UDP,
        _ => return None,
    };
    let dport: u16 = it.next()?.trim().parse().ok()?;
    let dest_ip: Ipv4Addr = it.next()?.trim().parse().ok()?;
    let dest_port: u16 = it.next()?.trim().parse().ok()?;
    if it.next().is_some() {
        return None; // trailing junk
    }
    Some(Forward {
        proto,
        dport,
        dest_ip,
        dest_port,
    })
}

/// Parse the comma-separated `forward` list, skipping malformed entries.
fn parse_forwards(spec: &str) -> Vec<Forward> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(parse_forward)
        .collect()
}

pub fn run(args: &[String]) -> i32 {
    if args.first().map(|s| s.as_str()) == Some("flush") {
        // (re)programming NEWTABLE re-creates idempotently; a true flush would
        // send NFT_MSG_DELTABLE — left out to keep this minimal.
        eprintln!("fw: flush not implemented; reprogramming is idempotent");
    }
    let cfg = Config::load();
    enable_forwarding();
    let lan = cfg.get_or("lan", "ifname", "br-lan");
    let masq = cfg.get_or("firewall", "masq", "1") == "1";
    let forwards = parse_forwards(cfg.get_or("firewall", "forward", ""));

    let buf = build_ruleset(lan, masq, &forwards);
    match program(&buf) {
        Ok(()) => {
            println!(
                "fw: ruleset loaded (input+forward filter, {}{} port-forward{})",
                if masq { "masquerade, " } else { "" },
                forwards.len(),
                if forwards.len() == 1 { "" } else { "s" }
            );
            0
        }
        Err(e) => {
            eprintln!("fw: programming nftables failed: {e}");
            1
        }
    }
}

fn enable_forwarding() {
    let _ = fs::write("/proc/sys/net/ipv4/ip_forward", "1\n");
    let _ = fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "1\n");
}

fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

/// Append the 4-byte `nfgenmsg` that opens every nf_tables message body.
fn nfgenmsg(b: &mut NlBuf, family: u8, res_id: u16) {
    b.bytes(&[family, 0]); // family, version NFNETLINK_V0
    b.bytes(&res_id.to_be_bytes());
}

/// `NFTA_DATA_VALUE` carrying raw value bytes (used inside cmp/bitwise).
fn value_data(b: &mut NlBuf, bytes: &[u8]) {
    let s = b.begin_nested(NFTA_DATA_VALUE);
    b.bytes(bytes);
    b.end_nested(s);
}

/// One expression-list element: `{ EXPR_NAME = name, EXPR_DATA = <build> }`.
fn expr(b: &mut NlBuf, name: &str, build_data: impl FnOnce(&mut NlBuf)) {
    let elem = b.begin_nested(NFTA_LIST_ELEM);
    b.attr_str(NFTA_EXPR_NAME, name);
    let data = b.begin_nested(NFTA_EXPR_DATA);
    build_data(b);
    b.end_nested(data);
    b.end_nested(elem);
}

/// An `immediate` expression setting the verdict register to `code`.
fn verdict_expr(b: &mut NlBuf, code: u32) {
    expr(b, "immediate", |b| {
        b.attr_u32_be(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        let data = b.begin_nested(NFTA_IMMEDIATE_DATA);
        let verdict = b.begin_nested(NFTA_DATA_VERDICT);
        b.attr_u32_be(NFTA_VERDICT_CODE, code);
        b.end_nested(verdict);
        b.end_nested(data);
    });
}

/// An `immediate` expression loading raw bytes into a data register.
fn immediate_value(b: &mut NlBuf, reg: u32, bytes: &[u8]) {
    expr(b, "immediate", |b| {
        b.attr_u32_be(NFTA_IMMEDIATE_DREG, reg);
        let data = b.begin_nested(NFTA_IMMEDIATE_DATA);
        value_data(b, bytes);
        b.end_nested(data);
    });
}

/// `meta <key>` loaded into a register.
fn meta_load(b: &mut NlBuf, key: u32, reg: u32) {
    expr(b, "meta", |b| {
        b.attr_u32_be(NFTA_META_KEY, key);
        b.attr_u32_be(NFTA_META_DREG, reg);
    });
}

/// `payload @<base>,<offset>,<len>` loaded into a register.
fn payload_load(b: &mut NlBuf, base: u32, offset: u32, len: u32, reg: u32) {
    expr(b, "payload", |b| {
        b.attr_u32_be(NFTA_PAYLOAD_DREG, reg);
        b.attr_u32_be(NFTA_PAYLOAD_BASE, base);
        b.attr_u32_be(NFTA_PAYLOAD_OFFSET, offset);
        b.attr_u32_be(NFTA_PAYLOAD_LEN, len);
    });
}

/// `cmp <reg> <op> <bytes>`.
fn cmp(b: &mut NlBuf, reg: u32, op: u32, bytes: &[u8]) {
    expr(b, "cmp", |b| {
        b.attr_u32_be(NFTA_CMP_SREG, reg);
        b.attr_u32_be(NFTA_CMP_OP, op);
        let data = b.begin_nested(NFTA_CMP_DATA);
        value_data(b, bytes);
        b.end_nested(data);
    });
}

/// The three expressions that test `ct state & (established|related) != 0`,
/// leaving the result so a following verdict can act on a match.
fn ct_state_match(b: &mut NlBuf) {
    expr(b, "ct", |b| {
        b.attr_u32_be(NFTA_CT_KEY, NFT_CT_STATE);
        b.attr_u32_be(NFTA_CT_DREG, NFT_REG_1);
    });
    expr(b, "bitwise", |b| {
        b.attr_u32_be(NFTA_BITWISE_SREG, NFT_REG_1);
        b.attr_u32_be(NFTA_BITWISE_DREG, NFT_REG_1);
        b.attr_u32_be(NFTA_BITWISE_LEN, 4);
        let mask = b.begin_nested(NFTA_BITWISE_MASK);
        value_data(b, &(CT_ESTABLISHED | CT_RELATED).to_be_bytes());
        b.end_nested(mask);
        let xor = b.begin_nested(NFTA_BITWISE_XOR);
        value_data(b, &0u32.to_be_bytes());
        b.end_nested(xor);
    });
    cmp(b, NFT_REG_1, NFT_CMP_NEQ, &0u32.to_be_bytes());
}

/// Emit a NEWCHAIN base-chain message into the batch.
fn new_base_chain(
    b: &mut NlBuf,
    seq: &mut u32,
    name: &str,
    chain_type: &str,
    hook: u32,
    priority: u32,
    policy: u32,
) {
    let msg = b.begin_message(
        nft_type(NFT_MSG_NEWCHAIN),
        nl::NLM_F_REQUEST | nl::NLM_F_CREATE | nl::NLM_F_ACK,
        *seq,
    );
    nfgenmsg(b, NFPROTO_INET, 0);
    b.attr_str(NFTA_CHAIN_TABLE, TABLE);
    b.attr_str(NFTA_CHAIN_NAME, name);
    let hook_s = b.begin_nested(NFTA_CHAIN_HOOK);
    b.attr_u32_be(NFTA_HOOK_HOOKNUM, hook);
    b.attr_u32_be(NFTA_HOOK_PRIORITY, priority);
    b.end_nested(hook_s);
    b.attr_str(NFTA_CHAIN_TYPE, chain_type);
    b.attr_u32_be(NFTA_CHAIN_POLICY, policy);
    b.end_message(msg);
    *seq += 1;
}

/// Emit a NEWRULE message whose expression list is produced by `build_exprs`.
fn new_rule(b: &mut NlBuf, seq: &mut u32, chain: &str, build_exprs: impl FnOnce(&mut NlBuf)) {
    let msg = b.begin_message(
        nft_type(NFT_MSG_NEWRULE),
        nl::NLM_F_REQUEST | nl::NLM_F_CREATE | nl::NLM_F_ACK,
        *seq,
    );
    nfgenmsg(b, NFPROTO_INET, 0);
    b.attr_str(NFTA_RULE_TABLE, TABLE);
    b.attr_str(NFTA_RULE_CHAIN, chain);
    let exprs = b.begin_nested(NFTA_RULE_EXPRESSIONS);
    build_exprs(b);
    b.end_nested(exprs);
    b.end_message(msg);
    *seq += 1;
}

/// `ct state established,related accept` rule for `chain`.
fn rule_ct_accept(b: &mut NlBuf, seq: &mut u32, chain: &str) {
    new_rule(b, seq, chain, |b| {
        ct_state_match(b);
        verdict_expr(b, NF_ACCEPT);
    });
}

/// `iifname == ifname accept` rule for `chain`.
fn rule_iif_accept(b: &mut NlBuf, seq: &mut u32, chain: &str, ifname: &str) {
    let mut name = ifname.as_bytes().to_vec();
    name.push(0); // NUL terminated, as the kernel compares ifname buffers
    new_rule(b, seq, chain, |b| {
        meta_load(b, NFT_META_IIFNAME, NFT_REG_1);
        cmp(b, NFT_REG_1, NFT_CMP_EQ, &name);
        verdict_expr(b, NF_ACCEPT);
    });
}

/// `meta l4proto == proto accept` rule for `chain` (used to allow ICMP).
fn rule_l4proto_accept(b: &mut NlBuf, seq: &mut u32, chain: &str, proto: u8) {
    new_rule(b, seq, chain, |b| {
        meta_load(b, NFT_META_L4PROTO, NFT_REG_1);
        cmp(b, NFT_REG_1, NFT_CMP_EQ, &[proto]);
        verdict_expr(b, NF_ACCEPT);
    });
}

/// prerouting DNAT rule: match `l4proto`+`dport`, rewrite to `dest_ip:dest_port`.
fn rule_dnat(b: &mut NlBuf, seq: &mut u32, fwd: &Forward) {
    new_rule(b, seq, "prerouting", |b| {
        meta_load(b, NFT_META_L4PROTO, NFT_REG_1);
        cmp(b, NFT_REG_1, NFT_CMP_EQ, &[fwd.proto]);
        // transport dport at offset 2, len 2 (same for TCP and UDP)
        payload_load(b, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG_1);
        cmp(b, NFT_REG_1, NFT_CMP_EQ, &fwd.dport.to_be_bytes());
        // load rewrite target: addr in reg1, port in reg2
        immediate_value(b, NFT_REG_1, &fwd.dest_ip.octets());
        immediate_value(b, NFT_REG_2, &fwd.dest_port.to_be_bytes());
        expr(b, "nat", |b| {
            b.attr_u32_be(NFTA_NAT_TYPE, NFT_NAT_DNAT);
            b.attr_u32_be(NFTA_NAT_FAMILY, NFPROTO_IPV4);
            b.attr_u32_be(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
            b.attr_u32_be(NFTA_NAT_REG_PROTO_MIN, NFT_REG_2);
        });
    });
}

/// forward-chain accept for traffic that the DNAT rule has already rewritten to
/// `dest_ip:dest_port` — required because the chain policy is drop.
fn rule_forward_to_dest(b: &mut NlBuf, seq: &mut u32, fwd: &Forward) {
    new_rule(b, seq, "forward", |b| {
        meta_load(b, NFT_META_L4PROTO, NFT_REG_1);
        cmp(b, NFT_REG_1, NFT_CMP_EQ, &[fwd.proto]);
        // ip daddr at network header offset 16, len 4
        payload_load(b, NFT_PAYLOAD_NETWORK_HEADER, 16, 4, NFT_REG_1);
        cmp(b, NFT_REG_1, NFT_CMP_EQ, &fwd.dest_ip.octets());
        payload_load(b, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG_1);
        cmp(b, NFT_REG_1, NFT_CMP_EQ, &fwd.dest_port.to_be_bytes());
        verdict_expr(b, NF_ACCEPT);
    });
}

/// Build the complete nf_tables batch (pure: no I/O), so it can be unit-tested.
fn build_ruleset(lan: &str, masq: bool, forwards: &[Forward]) -> NlBuf {
    let mut seq = 1u32;
    let mut b = NlBuf::new();

    // BATCH_BEGIN
    let bb = b.begin_message(NFNL_MSG_BATCH_BEGIN, nl::NLM_F_REQUEST, seq);
    nfgenmsg(&mut b, 0, NFNL_SUBSYS_NFTABLES);
    b.end_message(bb);
    seq += 1;

    // NEWTABLE inet lwrt
    let tbl = b.begin_message(
        nft_type(NFT_MSG_NEWTABLE),
        nl::NLM_F_REQUEST | nl::NLM_F_CREATE | nl::NLM_F_ACK,
        seq,
    );
    nfgenmsg(&mut b, NFPROTO_INET, 0);
    b.attr_str(NFTA_TABLE_NAME, TABLE);
    b.end_message(tbl);
    seq += 1;

    // Base chains. NAT prerouting uses the conventional dstnat priority (-100);
    // postrouting uses srcnat priority (100).
    let dstnat_prio = (-100i32) as u32;
    new_base_chain(&mut b, &mut seq, "input", "filter", NF_INET_LOCAL_IN, 0, NF_DROP);
    new_base_chain(&mut b, &mut seq, "forward", "filter", NF_INET_FORWARD, 0, NF_DROP);
    new_base_chain(&mut b, &mut seq, "prerouting", "nat", NF_INET_PRE_ROUTING, dstnat_prio, NF_ACCEPT);
    new_base_chain(&mut b, &mut seq, "postrouting", "nat", NF_INET_POST_ROUTING, 100, NF_ACCEPT);

    // input: protect the router itself but keep it reachable from the LAN.
    rule_ct_accept(&mut b, &mut seq, "input");
    rule_iif_accept(&mut b, &mut seq, "input", "lo");
    rule_iif_accept(&mut b, &mut seq, "input", lan);
    rule_l4proto_accept(&mut b, &mut seq, "input", IPPROTO_ICMP);

    // forward: established back-traffic + LAN egress, plus any port-forwards.
    rule_ct_accept(&mut b, &mut seq, "forward");
    rule_iif_accept(&mut b, &mut seq, "forward", lan);
    for f in forwards {
        rule_forward_to_dest(&mut b, &mut seq, f);
    }

    // prerouting: DNAT each port-forward.
    for f in forwards {
        rule_dnat(&mut b, &mut seq, f);
    }

    // postrouting: masquerade LAN traffic out the WAN.
    if masq {
        new_rule(&mut b, &mut seq, "postrouting", |b| {
            expr(b, "masq", |_| {});
        });
    }

    // BATCH_END
    let be = b.begin_message(NFNL_MSG_BATCH_END, nl::NLM_F_REQUEST, seq);
    nfgenmsg(&mut b, 0, NFNL_SUBSYS_NFTABLES);
    b.end_message(be);

    b
}

/// Send a prepared batch and drain the ACKs, reporting the first hard error.
fn program(buf: &NlBuf) -> std::io::Result<()> {
    let fd = nl::open(NETLINK_NETFILTER)?;
    nl::send(fd, buf.as_slice())?;
    let mut result = Ok(());
    for _ in 0..32 {
        match nl::recv_ack(fd) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => break,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    nl::close(fd);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forward_accepts_well_formed() {
        let f = parse_forward("tcp:8080:192.168.1.10:80").unwrap();
        assert_eq!(
            f,
            Forward {
                proto: IPPROTO_TCP,
                dport: 8080,
                dest_ip: Ipv4Addr::new(192, 168, 1, 10),
                dest_port: 80,
            }
        );
        assert_eq!(parse_forward("UDP:53:10.0.0.2:53").unwrap().proto, IPPROTO_UDP);
    }

    #[test]
    fn parse_forward_rejects_garbage() {
        assert!(parse_forward("sctp:1:2.2.2.2:1").is_none()); // bad proto
        assert!(parse_forward("tcp:notaport:1.2.3.4:80").is_none());
        assert!(parse_forward("tcp:80:999.1.1.1:80").is_none()); // bad ip
        assert!(parse_forward("tcp:80:1.2.3.4").is_none()); // too few fields
        assert!(parse_forward("tcp:80:1.2.3.4:80:extra").is_none()); // trailing
    }

    #[test]
    fn parse_forwards_skips_blanks_and_bad() {
        let v = parse_forwards("tcp:80:1.2.3.4:80, , garbage, udp:53:1.2.3.4:53");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].dport, 80);
        assert_eq!(v[1].proto, IPPROTO_UDP);
    }

    /// Walk the batch and count nf_tables messages by sub-type, validating that
    /// every nlmsghdr length is self-consistent (sums back to the buffer size).
    fn count_msgs(buf: &[u8]) -> (usize, usize, usize) {
        let (mut chains, mut rules, mut tables) = (0, 0, 0);
        let mut pos = 0;
        while pos + 16 <= buf.len() {
            let len = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            let ty = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
            assert!(len >= 16 && pos + len <= buf.len(), "bad nlmsg len {len}");
            if ty >> 8 == NFNL_SUBSYS_NFTABLES {
                match ty & 0xff {
                    NFT_MSG_NEWTABLE => tables += 1,
                    NFT_MSG_NEWCHAIN => chains += 1,
                    NFT_MSG_NEWRULE => rules += 1,
                    _ => {}
                }
            }
            pos += nl::align4(len);
        }
        assert_eq!(pos, buf.len(), "messages did not tile the buffer exactly");
        (tables, chains, rules)
    }

    #[test]
    fn ruleset_without_forwards_has_expected_shape() {
        let buf = build_ruleset("br-lan", true, &[]);
        let (tables, chains, rules) = count_msgs(buf.as_slice());
        assert_eq!(tables, 1);
        assert_eq!(chains, 4); // input, forward, prerouting, postrouting
        // input: ct, lo, lan, icmp = 4; forward: ct, lan = 2; postrouting: masq = 1
        assert_eq!(rules, 7);
    }

    #[test]
    fn ruleset_with_forwards_adds_dnat_and_forward_accepts() {
        let fwds = parse_forwards("tcp:8080:192.168.1.10:80, udp:5000:192.168.1.20:5000");
        let buf = build_ruleset("br-lan", true, &fwds);
        let (_, chains, rules) = count_msgs(buf.as_slice());
        assert_eq!(chains, 4);
        // base 7 + 2 forward-accepts + 2 dnat = 11
        assert_eq!(rules, 11);
    }

    #[test]
    fn masq_disabled_drops_the_masquerade_rule() {
        let with = build_ruleset("br-lan", true, &[]);
        let without = build_ruleset("br-lan", false, &[]);
        let (_, _, r_with) = count_msgs(with.as_slice());
        let (_, _, r_without) = count_msgs(without.as_slice());
        assert_eq!(r_with - r_without, 1);
    }
}
