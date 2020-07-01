use std::net::Ipv6Addr;
use std::str;
use std::str::FromStr;

mod helper;

/// 返回原字典里数据
pub fn find_addr(ipaddr: &str) -> &'static str {
    if let Ok(ip6) = Ipv6Addr::from_str(ipaddr) {
        let ip_bytes = ip6.octets();
        let ip = u64::from_be_bytes(helper::to_array(&ip_bytes[0..8]));
        let i = helper::find(ip, 0, helper::IPV6_DATA.index_count);
        let o = helper::IPV6_DATA.first_index + i * (8 + helper::IPV6_DATA.offlen);
        let o2 = helper::get_int(o + 8, helper::IPV6_DATA.offlen);
        return helper::get_addr(o2)[0];
    }
    ""
}

/// 返回分割, 并兼容 iddb v4 的地址名格式
pub fn find_addr_vec(addr: &str) -> [String; 4] {
    helper::split(find_addr(addr))
}



