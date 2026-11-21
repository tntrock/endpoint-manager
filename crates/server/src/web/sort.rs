//! 表格的伺服器端排序：網址參數 `sort=<欄位>`（遞減加 `-`），欄位對應白名單 SQL。

/// 表格的一欄
pub struct Column {
    pub key: &'static str,
    pub label: &'static str,
    /// 排序用的 SQL 運算式；空字串表示這欄不能排序
    pub sql: &'static str,
    /// 第一次點時先遞減（時間欄位）
    pub desc_first: bool,
    /// 數字欄（靠右）
    pub num: bool,
}

impl Column {
    pub const fn new(key: &'static str, label: &'static str, sql: &'static str) -> Column {
        Column {
            key,
            label,
            sql,
            desc_first: false,
            num: false,
        }
    }

    pub const fn desc_first(mut self) -> Column {
        self.desc_first = true;
        self
    }

    pub const fn num(mut self) -> Column {
        self.num = true;
        self
    }

    pub const fn fixed(label: &'static str) -> Column {
        Column::new("", label, "")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sort {
    /// 欄位在 `cols` 的位置
    pub col: usize,
    pub desc: bool,
}

impl Sort {
    /// 解析網址參數；不認得的值用 `default`（欄位 key, 是否遞減）
    pub fn parse(raw: &str, cols: &[Column], default: (&str, bool)) -> Sort {
        let (key, desc) = match raw.strip_prefix('-') {
            Some(k) => (k, true),
            None => (raw, false),
        };
        let find = |k: &str| cols.iter().position(|c| !c.sql.is_empty() && c.key == k);
        match find(key) {
            Some(col) => Sort { col, desc },
            None => Sort {
                col: find(default.0).expect("default sort column"),
                desc: default.1,
            },
        }
    }

    /// 網址參數的值
    pub fn param(&self, cols: &[Column]) -> String {
        format!("{}{}", if self.desc { "-" } else { "" }, cols[self.col].key)
    }

    /// `ORDER BY` 的內容（呼叫端再接上穩定次序）。只會產生白名單裡的 SQL
    pub fn order_by(&self, cols: &[Column]) -> String {
        format!(
            "{} {} NULLS LAST",
            cols[self.col].sql,
            if self.desc { "DESC" } else { "ASC" }
        )
    }
}

/// 表頭的一格
pub struct Header {
    pub label: &'static str,
    /// 點了之後的網址；None 表示不能排序
    pub url: Option<String>,
    /// `aria-sort` 的值；空字串表示不是目前排序的欄位
    pub aria: &'static str,
    pub arrow: &'static str,
    pub num: bool,
}

/// `url_for(sort 參數)` 產生保留其他條件的網址
pub fn headers(cols: &[Column], sort: Sort, url_for: impl Fn(&str) -> String) -> Vec<Header> {
    cols.iter()
        .enumerate()
        .map(|(i, c)| {
            let current = i == sort.col;
            let next_desc = if current { !sort.desc } else { c.desc_first };
            Header {
                label: c.label,
                url: (!c.sql.is_empty())
                    .then(|| url_for(&format!("{}{}", if next_desc { "-" } else { "" }, c.key))),
                aria: match (current, sort.desc) {
                    (false, _) => "",
                    (true, false) => "ascending",
                    (true, true) => "descending",
                },
                arrow: match (current, sort.desc) {
                    (false, _) => "",
                    (true, false) => " ▲",
                    (true, true) => " ▼",
                },
                num: c.num,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLS: [Column; 3] = [
        Column::new("name", "名稱", "lower(x.name)"),
        Column::fixed("說明"),
        Column::new("seen", "最後回報", "x.seen").desc_first(),
    ];

    #[test]
    fn parse_and_sql() {
        let s = Sort::parse("-name", &COLS, ("seen", true));
        assert_eq!(s, Sort { col: 0, desc: true });
        assert_eq!(s.order_by(&COLS), "lower(x.name) DESC NULLS LAST");
        assert_eq!(s.param(&COLS), "-name");
        // 不認得、不能排序的欄位、注入字串都用預設
        for raw in ["", "nope", "-", "說明", "name; DROP TABLE x"] {
            assert_eq!(
                Sort::parse(raw, &COLS, ("seen", true)),
                Sort { col: 2, desc: true }
            );
        }
    }

    #[test]
    fn columns_built_at_runtime() {
        let name = std::hint::black_box("名稱");
        let c = Column::new("k", name, "x.k").desc_first();
        assert!(c.desc_first && !c.num && c.label == "名稱");
        assert!(Column::new("n", name, "x.n").num().num);
        let f = Column::fixed(name);
        assert!(f.sql.is_empty() && f.key.is_empty());
    }

    #[test]
    fn header_links_toggle() {
        let s = Sort::parse("name", &COLS, ("name", false));
        let h = headers(&COLS, s, |p| format!("/x?sort={p}"));
        assert_eq!(h[0].url.as_deref(), Some("/x?sort=-name"));
        assert_eq!((h[0].aria, h[0].arrow), ("ascending", " ▲"));
        assert!(h[1].url.is_none());
        // 時間欄位第一次點是遞減
        assert_eq!(h[2].url.as_deref(), Some("/x?sort=-seen"));
        assert_eq!(h[2].aria, "");
        let s = Sort::parse("-name", &COLS, ("name", false));
        let h = headers(&COLS, s, |p| format!("/x?sort={p}"));
        assert_eq!(h[0].url.as_deref(), Some("/x?sort=name"));
        assert_eq!(h[0].arrow, " ▼");
    }
}
