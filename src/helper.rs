use lazy_static::lazy_static;
use std::collections::HashSet;
use std::fs;
use std::convert::TryInto;

const FILE_NAME: &str = "ipv6wry.db";

pub struct IPV6Object {
    pub data: Vec<u8>,
    pub first_index: u32,
    pub index_count: u32,
    pub offlen: u32,
}

fn get_ipv4_name(d: &str) -> String {
    let s = d.replace("自治区", "");
    let s = s.replace("省", "");
    let s = s.replace("市", "");
    s.replace("区", "")
}

fn get_city_name(d: &str) -> String {
    d.replace("市", "")
}

pub fn split(addr: &str) -> [String; 4] {
    let mut addres: [String; 4] = Default::default();
    if addr.starts_with("中国") {
        let mut addr1 = addr.replace("中国", "");
        addres[0] = "中国".to_string();
        for prefix in LEVEL1_SET.iter() {
            if addr1.starts_with(prefix) {
                addr1 = addr1.replace(prefix, "");
                let clean_level1 = get_ipv4_name(prefix);
                addres[1] = clean_level1;
                break;
            }
        }

        for prefix in LEVEL2_SET.iter() {
            if addr1.starts_with(prefix) {
                addr1 = addr1.replace(prefix, "");
                let clean_leve2 = get_city_name(prefix);
                addres[2] = clean_leve2;
                break;
            }
        }
        addres[3] = addr1;
    } else {
        let mut is_china = false;
        let mut addr1 = addr.to_string();
        for prefix in LEVEL1_SET.iter() {
            if addr1.starts_with(prefix) {
                addr1 = addr1.replace(prefix, "");
                addres[0] = "中国".to_string();
                addres[1] = get_ipv4_name(prefix);
                is_china = true;
                break;
            }
        }
        if is_china {
            addr1 = addr.to_string();
            for prefix in LEVEL2_SET.iter() {
                if addr1.starts_with(prefix) {
                    addr1 = addr1.replace(prefix, "");
                    addres[2] = get_city_name(prefix);
                    break;
                }
            }
            addres[3] = addr1;
        } else {
            addres[0] = addr.to_string();
        }
    }

    addres
}

pub fn get_addr(offset: u32) -> Vec<&'static str> {
    let mut o = offset;
    let b = IPV6_DATA.data[o as usize];
    if b == 1 {
        return get_addr(get_int(o + 1, IPV6_DATA.offlen));
    }
    let c_area = get_area_addr(o);
    if b == 2 {
        o += 1 + IPV6_DATA.offlen;
    } else {
        o = offset + find_string_end_offset(o) + 1;
    }
    let a_area = get_area_addr(o);
    return vec![c_area, a_area];
}

fn get_area_addr(offset: u32) -> &'static str {
    let b = IPV6_DATA.data[offset as usize];
    if b == 1 || b == 2 {
        let p = get_int(offset + 1, IPV6_DATA.offlen);
        return get_area_addr(p);
    }
    get_string(offset).trim()
}

fn get_string(offset: u32) -> &'static str {
    let length = find_string_end_offset(offset) as usize;
    let offset = offset as usize;
    unsafe { std::str::from_utf8_unchecked(&IPV6_DATA.data[offset..(offset + length)]) }
}

fn find_string_end_offset(offset: u32) -> u32 {
    let mut i: usize = 1;
    let offset = offset as usize;
    loop {
        let b = IPV6_DATA.data[offset + i];
        if b == b'\0' {
            break;
        }
        i += 1;
    }
    i as u32
}

pub fn get_int(start: u32, len: u32) -> u32 {
    let start = start as usize;
    if len == 3 {
        return u32::from_le_bytes([
            IPV6_DATA.data[start],
            IPV6_DATA.data[start + 1],
            IPV6_DATA.data[start + 2],
            0,
        ]);
    }
    if len == 2 {
        return u32::from_le_bytes([IPV6_DATA.data[start], IPV6_DATA.data[start + 1], 0, 0]);
    }

    if len == 2 {
        return u32::from_le_bytes([IPV6_DATA.data[start], 0, 0, 0]);
    }
    u32::from_le_bytes([
        IPV6_DATA.data[start],
        IPV6_DATA.data[start + 1],
        IPV6_DATA.data[start + 2],
        IPV6_DATA.data[start + 3],
    ])
}

pub fn find(ip: u64, l: u32, r: u32) -> u32 {
    if r - l <= 1 {
        return l;
    }
    let m = (l + r) / 2;
    let o = (IPV6_DATA.first_index + m * (8 + IPV6_DATA.offlen)) as usize;

    let new_ip = u64::from_le_bytes(to_array(&IPV6_DATA.data[o..(o + 8)]));
    if ip < new_ip {
        return find(ip, l, m);
    }
    find(ip, m, r)
}


fn check(b: &[u8]) {
    let ipdb = unsafe { std::str::from_utf8_unchecked(&b[0..4]) };
    let version = u8::from_le_bytes([b[4]]);
    println!("ipdb magic {}, version {}", ipdb, version);

    if ipdb != "IPDB" {
        panic!("数据库格式错误之魔法值");
    }
    if version > 1 {
        panic!("数据库格式错误之版本值");
    }
}

pub fn to_array(barry: &[u8]) -> [u8; 8] {
    barry.try_into().expect("slice with incorrect length")
}

/**
ipdb magic IPDB, version 1
first_index 428877
index_count 109067
offlen 3
 */
fn init_ipv6(ipv6object: &mut IPV6Object) {
    let file_bytes = fs::read(FILE_NAME).unwrap_or_else(|_| panic!("can not open file {}!", FILE_NAME));
    check(&file_bytes);

    let offlen = file_bytes[6] as u32;
    ipv6object.offlen = offlen;

    let index_count = u64::from_le_bytes(to_array(&file_bytes[8..16]));
    let first_index = u64::from_le_bytes(to_array(&file_bytes[16..24]));
    println!("first_index {}", first_index);
    println!("index_count {}", index_count);
    println!("offlen {}", offlen);

    ipv6object.index_count = index_count as u32;
    ipv6object.first_index = first_index as u32;
    ipv6object.data = file_bytes;
}

// 初始化
lazy_static! {
    pub static ref IPV6_DATA: IPV6Object = {
        let  mut tmp = IPV6Object {
            first_index: 0,
            index_count: 0,
            data: Vec::new(),
            offlen: 0,
        };
        init_ipv6(&mut tmp);
        tmp
    };

    static ref LEVEL2_SET: HashSet<&'static str> = {
        let mut tmp_set = HashSet::new();
        tmp_set.insert("石家庄市");
        tmp_set.insert("唐山市");
        tmp_set.insert("秦皇岛市");
        tmp_set.insert("邯郸市");
        tmp_set.insert("邢台市");
        tmp_set.insert("保定市");
        tmp_set.insert("张家口市");
        tmp_set.insert("承德市");
        tmp_set.insert("沧州市");
        tmp_set.insert("廊坊市");
        tmp_set.insert("衡水市");
        tmp_set.insert("太原市");
        tmp_set.insert("大同市");
        tmp_set.insert("阳泉市");
        tmp_set.insert("长治市");
        tmp_set.insert("晋城市");
        tmp_set.insert("朔州市");
        tmp_set.insert("晋中市");
        tmp_set.insert("运城市");
        tmp_set.insert("忻州市");
        tmp_set.insert("临汾市");
        tmp_set.insert("吕梁市");
        tmp_set.insert("呼和浩特市");
        tmp_set.insert("包头市");
        tmp_set.insert("乌海市");
        tmp_set.insert("赤峰市");
        tmp_set.insert("通辽市");
        tmp_set.insert("鄂尔多斯市");
        tmp_set.insert("呼伦贝尔市");
        tmp_set.insert("巴彦淖尔市");
        tmp_set.insert("乌兰察布市");
        tmp_set.insert("沈阳市");
        tmp_set.insert("大连市");
        tmp_set.insert("鞍山市");
        tmp_set.insert("抚顺市");
        tmp_set.insert("本溪市");
        tmp_set.insert("丹东市");
        tmp_set.insert("锦州市");
        tmp_set.insert("营口市");
        tmp_set.insert("阜新市");
        tmp_set.insert("辽阳市");
        tmp_set.insert("盘锦市");
        tmp_set.insert("铁岭市");
        tmp_set.insert("朝阳市");
        tmp_set.insert("葫芦岛市");
        tmp_set.insert("长春市");
        tmp_set.insert("吉林市");
        tmp_set.insert("四平市");
        tmp_set.insert("辽源市");
        tmp_set.insert("通化市");
        tmp_set.insert("白山市");
        tmp_set.insert("松原市");
        tmp_set.insert("白城市");
        tmp_set.insert("哈尔滨市");
        tmp_set.insert("齐齐哈尔市");
        tmp_set.insert("鸡西市");
        tmp_set.insert("鹤岗市");
        tmp_set.insert("双鸭山市");
        tmp_set.insert("大庆市");
        tmp_set.insert("伊春市");
        tmp_set.insert("佳木斯市");
        tmp_set.insert("七台河市");
        tmp_set.insert("牡丹江市");
        tmp_set.insert("黑河市");
        tmp_set.insert("绥化市");
        tmp_set.insert("南京市");
        tmp_set.insert("无锡市");
        tmp_set.insert("徐州市");
        tmp_set.insert("常州市");
        tmp_set.insert("苏州市");
        tmp_set.insert("南通市");
        tmp_set.insert("连云港市");
        tmp_set.insert("淮安市");
        tmp_set.insert("盐城市");
        tmp_set.insert("扬州市");
        tmp_set.insert("镇江市");
        tmp_set.insert("泰州市");
        tmp_set.insert("宿迁市");
        tmp_set.insert("杭州市");
        tmp_set.insert("宁波市");
        tmp_set.insert("温州市");
        tmp_set.insert("嘉兴市");
        tmp_set.insert("湖州市");
        tmp_set.insert("绍兴市");
        tmp_set.insert("金华市");
        tmp_set.insert("衢州市");
        tmp_set.insert("舟山市");
        tmp_set.insert("台州市");
        tmp_set.insert("丽水市");
        tmp_set.insert("合肥市");
        tmp_set.insert("芜湖市");
        tmp_set.insert("蚌埠市");
        tmp_set.insert("淮南市");
        tmp_set.insert("马鞍山市");
        tmp_set.insert("淮北市");
        tmp_set.insert("铜陵市");
        tmp_set.insert("安庆市");
        tmp_set.insert("黄山市");
        tmp_set.insert("滁州市");
        tmp_set.insert("阜阳市");
        tmp_set.insert("宿州市");
        tmp_set.insert("六安市");
        tmp_set.insert("亳州市");
        tmp_set.insert("池州市");
        tmp_set.insert("宣城市");
        tmp_set.insert("福州市");
        tmp_set.insert("厦门市");
        tmp_set.insert("莆田市");
        tmp_set.insert("三明市");
        tmp_set.insert("泉州市");
        tmp_set.insert("漳州市");
        tmp_set.insert("南平市");
        tmp_set.insert("龙岩市");
        tmp_set.insert("宁德市");
        tmp_set.insert("南昌市");
        tmp_set.insert("景德镇市");
        tmp_set.insert("萍乡市");
        tmp_set.insert("九江市");
        tmp_set.insert("抚州市");
        tmp_set.insert("鹰潭市");
        tmp_set.insert("赣州市");
        tmp_set.insert("吉安市");
        tmp_set.insert("宜春市");
        tmp_set.insert("新余市");
        tmp_set.insert("上饶市");
        tmp_set.insert("济南市");
        tmp_set.insert("青岛市");
        tmp_set.insert("淄博市");
        tmp_set.insert("枣庄市");
        tmp_set.insert("东营市");
        tmp_set.insert("烟台市");
        tmp_set.insert("潍坊市");
        tmp_set.insert("济宁市");
        tmp_set.insert("泰安市");
        tmp_set.insert("威海市");
        tmp_set.insert("日照市");
        tmp_set.insert("临沂市");
        tmp_set.insert("德州市");
        tmp_set.insert("聊城市");
        tmp_set.insert("滨州市");
        tmp_set.insert("菏泽市");
        tmp_set.insert("郑州市");
        tmp_set.insert("开封市");
        tmp_set.insert("洛阳市");
        tmp_set.insert("平顶山市");
        tmp_set.insert("安阳市");
        tmp_set.insert("鹤壁市");
        tmp_set.insert("新乡市");
        tmp_set.insert("焦作市");
        tmp_set.insert("濮阳市");
        tmp_set.insert("许昌市");
        tmp_set.insert("漯河市");
        tmp_set.insert("三门峡市");
        tmp_set.insert("南阳市");
        tmp_set.insert("商丘市");
        tmp_set.insert("信阳市");
        tmp_set.insert("周口市");
        tmp_set.insert("驻马店市");
        tmp_set.insert("武汉市");
        tmp_set.insert("黄石市");
        tmp_set.insert("十堰市");
        tmp_set.insert("宜昌市");
        tmp_set.insert("襄阳市");
        tmp_set.insert("鄂州市");
        tmp_set.insert("荆门市");
        tmp_set.insert("孝感市");
        tmp_set.insert("荆州市");
        tmp_set.insert("黄冈市");
        tmp_set.insert("咸宁市");
        tmp_set.insert("随州市");
        tmp_set.insert("长沙市");
        tmp_set.insert("株洲市");
        tmp_set.insert("湘潭市");
        tmp_set.insert("衡阳市");
        tmp_set.insert("邵阳市");
        tmp_set.insert("岳阳市");
        tmp_set.insert("常德市");
        tmp_set.insert("张家界市");
        tmp_set.insert("益阳市");
        tmp_set.insert("郴州市");
        tmp_set.insert("永州市");
        tmp_set.insert("怀化市");
        tmp_set.insert("娄底市");
        tmp_set.insert("广州市");
        tmp_set.insert("韶关市");
        tmp_set.insert("深圳市");
        tmp_set.insert("珠海市");
        tmp_set.insert("汕头市");
        tmp_set.insert("佛山市");
        tmp_set.insert("江门市");
        tmp_set.insert("湛江市");
        tmp_set.insert("茂名市");
        tmp_set.insert("肇庆市");
        tmp_set.insert("惠州市");
        tmp_set.insert("梅州市");
        tmp_set.insert("汕尾市");
        tmp_set.insert("河源市");
        tmp_set.insert("阳江市");
        tmp_set.insert("清远市");
        tmp_set.insert("东莞市");
        tmp_set.insert("中山市");
        tmp_set.insert("潮州市");
        tmp_set.insert("揭阳市");
        tmp_set.insert("云浮市");
        tmp_set.insert("南宁市");
        tmp_set.insert("柳州市");
        tmp_set.insert("桂林市");
        tmp_set.insert("梧州市");
        tmp_set.insert("北海市");
        tmp_set.insert("防城港市");
        tmp_set.insert("钦州市");
        tmp_set.insert("贵港市");
        tmp_set.insert("玉林市");
        tmp_set.insert("百色市");
        tmp_set.insert("贺州市");
        tmp_set.insert("河池市");
        tmp_set.insert("来宾市");
        tmp_set.insert("崇左市");
        tmp_set.insert("海口市");
        tmp_set.insert("三亚市");
        tmp_set.insert("三沙市");
        tmp_set.insert("儋州市");
        tmp_set.insert("成都市");
        tmp_set.insert("自贡市");
        tmp_set.insert("攀枝花市");
        tmp_set.insert("泸州市");
        tmp_set.insert("德阳市");
        tmp_set.insert("绵阳市");
        tmp_set.insert("广元市");
        tmp_set.insert("遂宁市");
        tmp_set.insert("内江市");
        tmp_set.insert("乐山市");
        tmp_set.insert("南充市");
        tmp_set.insert("眉山市");
        tmp_set.insert("宜宾市");
        tmp_set.insert("广安市");
        tmp_set.insert("达州市");
        tmp_set.insert("雅安市");
        tmp_set.insert("巴中市");
        tmp_set.insert("资阳市");
        tmp_set.insert("贵阳市");
        tmp_set.insert("六盘水市");
        tmp_set.insert("遵义市");
        tmp_set.insert("安顺市");
        tmp_set.insert("毕节市");
        tmp_set.insert("铜仁市");
        tmp_set.insert("昆明市");
        tmp_set.insert("曲靖市");
        tmp_set.insert("玉溪市");
        tmp_set.insert("保山市");
        tmp_set.insert("昭通市");
        tmp_set.insert("丽江市");
        tmp_set.insert("普洱市");
        tmp_set.insert("临沧市");
        tmp_set.insert("拉萨市");
        tmp_set.insert("日喀则市");
        tmp_set.insert("昌都市");
        tmp_set.insert("林芝市");
        tmp_set.insert("山南市");
        tmp_set.insert("那曲市");
        tmp_set.insert("西安市");
        tmp_set.insert("铜川市");
        tmp_set.insert("宝鸡市");
        tmp_set.insert("咸阳市");
        tmp_set.insert("渭南市");
        tmp_set.insert("延安市");
        tmp_set.insert("汉中市");
        tmp_set.insert("榆林市");
        tmp_set.insert("安康市");
        tmp_set.insert("商洛市");
        tmp_set.insert("兰州市");
        tmp_set.insert("嘉峪关市");
        tmp_set.insert("金昌市");
        tmp_set.insert("白银市");
        tmp_set.insert("天水市");
        tmp_set.insert("武威市");
        tmp_set.insert("张掖市");
        tmp_set.insert("平凉市");
        tmp_set.insert("酒泉市");
        tmp_set.insert("庆阳市");
        tmp_set.insert("定西市");
        tmp_set.insert("陇南市");
        tmp_set.insert("西宁市");
        tmp_set.insert("海东市");
        tmp_set.insert("西宁市");
        tmp_set.insert("海东市");
        tmp_set.insert("乌鲁木齐市");
        tmp_set.insert("克拉玛依市");
        tmp_set.insert("吐鲁番市");
        tmp_set.insert("哈密市");

        //二级地区
        tmp_set.insert("大兴安岭地区");
        tmp_set.insert("阿里地区");
        tmp_set.insert("阿克苏地区");
        tmp_set.insert("喀什地区");
        tmp_set.insert("和田地区");
        tmp_set.insert("塔城地区");
        tmp_set.insert("阿勒泰地区");

        //自治州
        tmp_set.insert("临夏回族自治州");
        tmp_set.insert("临夏州");

        tmp_set.insert("甘南藏族自治州");
        tmp_set.insert("甘南州");

        tmp_set.insert("黔东南苗族侗族自治州");
        tmp_set.insert("黔东南州");

        tmp_set.insert("黔南布依族苗族自治州");
        tmp_set.insert("黔南州");

        tmp_set.insert("黔西南布依族苗族自治州");
        tmp_set.insert("黔西南州");

        tmp_set.insert("恩施土家族苗族自治州");
        tmp_set.insert("恩施州");

        tmp_set.insert("湘西土家族苗族自治州");
        tmp_set.insert("湘西州");

        tmp_set.insert("延边朝鲜族自治州");
        tmp_set.insert("延边州");

        tmp_set.insert("海北藏族自治州");
        tmp_set.insert("海北州");

        tmp_set.insert("海南藏族自治州");
        tmp_set.insert("海南州");

        tmp_set.insert("黄南藏族自治州");
        tmp_set.insert("黄南州");

        tmp_set.insert("果洛藏族自治州");
        tmp_set.insert("果洛州");

        tmp_set.insert("玉树藏族自治州");
        tmp_set.insert("玉树州");

        tmp_set.insert("海西蒙古族藏族自治州");
        tmp_set.insert("海西州");

        tmp_set.insert("阿坝藏族羌族自治州");
        tmp_set.insert("阿坝州");

        tmp_set.insert("甘孜藏族自治州");
        tmp_set.insert("甘孜州");


        tmp_set.insert("凉山彝族自治州");
        tmp_set.insert("凉山州");

        tmp_set.insert("克孜勒苏柯尔克孜自治州");
        tmp_set.insert("克孜勒苏州");
        tmp_set.insert("克孜州");


        tmp_set.insert("博尔塔拉蒙古自治州");
        tmp_set.insert("博尔塔拉州");
        tmp_set.insert("博尔州");

        tmp_set.insert("昌吉回族自治州");
        tmp_set.insert("昌吉州");

        tmp_set.insert("巴音郭楞蒙古自治州");
        tmp_set.insert("巴音郭楞州");

        tmp_set.insert("伊犁哈萨克自治州");
        tmp_set.insert("伊犁州");

        tmp_set.insert("德宏傣族景颇族自治州");
        tmp_set.insert("德宏州");

        tmp_set.insert("怒江傈僳族自治州");
        tmp_set.insert("怒江州");

        tmp_set.insert("迪庆藏族自治州");
        tmp_set.insert("迪庆州");

        tmp_set.insert("大理白族自治州");
        tmp_set.insert("大理州");

        tmp_set.insert("楚雄彝族自治州");
        tmp_set.insert("楚雄州");

        tmp_set.insert("红河哈尼族彝族自治州");
        tmp_set.insert("红河州");

        tmp_set.insert("文山壮族苗族自治州");
        tmp_set.insert("文山州");

        tmp_set.insert("西双版纳傣族自治州");
        tmp_set.insert("西双版纳州");
        tmp_set

    };

    static ref LEVEL1_SET: HashSet<&'static str> = {
        let mut tmp_set = HashSet::new();
        tmp_set.insert("河北省");
        tmp_set.insert("山西省");
        tmp_set.insert("辽宁省");
        tmp_set.insert("吉林省");
        tmp_set.insert("黑龙江省");
        tmp_set.insert("江苏省");
        tmp_set.insert("浙江省");
        tmp_set.insert("安徽省");
        tmp_set.insert("福建省");
        tmp_set.insert("江西省");
        tmp_set.insert("山东省");
        tmp_set.insert("河南省");
        tmp_set.insert("湖北省");
        tmp_set.insert("湖南省");
        tmp_set.insert("广东省");
        tmp_set.insert("海南省");
        tmp_set.insert("四川省");
        tmp_set.insert("贵州省");
        tmp_set.insert("云南省");
        tmp_set.insert("陕西省");
        tmp_set.insert("甘肃省");
        tmp_set.insert("青海省");
        //特别行政区, 自治区, 自治市
        tmp_set.insert("内蒙古自治区");
        tmp_set.insert("内蒙古区");
        tmp_set.insert("广西壮族自治区");
        tmp_set.insert("广西区");
        tmp_set.insert("西藏自治区");
        tmp_set.insert("西藏区");
        tmp_set.insert("宁夏回族自治区");
        tmp_set.insert("宁夏区");
        tmp_set.insert("新疆维吾尔自治区");
        tmp_set.insert("新疆区");
        tmp_set.insert("北京市");
        tmp_set.insert("天津市");
        tmp_set.insert("上海市");
        tmp_set.insert("重庆市");
        tmp_set.insert("香港特别行政区");
        tmp_set.insert("香港区");
        tmp_set.insert("澳门特别行政区");
        tmp_set.insert("澳门区");
        tmp_set
    };
}