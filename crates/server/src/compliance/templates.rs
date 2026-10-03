//! 內建組態基準範本：內嵌的 baseline.json，每條對應一條規則。

use std::sync::OnceLock;

use serde::Deserialize;
use sqlx::PgPool;

use super::admin::{self, RuleInput};

#[derive(Debug, Deserialize)]
pub struct Template {
    pub key: String,
    pub category: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub kind: String,
    pub params: serde_json::Value,
    /// Microsoft 文件出處
    pub source: String,
}

/// 全部範本；內嵌 JSON 壞掉是程式錯誤，單元測試會先抓到。
pub fn all() -> &'static [Template] {
    static ALL: OnceLock<Vec<Template>> = OnceLock::new();
    ALL.get_or_init(|| {
        serde_json::from_str(include_str!("baseline.json")).expect("baseline.json 格式錯誤")
    })
}

/// 建立結果
#[derive(Debug, Default)]
pub struct Created {
    pub created: Vec<String>,
    /// 已經建立過而略過
    pub skipped: Vec<String>,
    /// (範本名稱, 錯誤)
    pub failed: Vec<(String, String)>,
}

/// 依 key 建立規則（啟用、全部裝置）；已建立過的略過，其他錯誤（例如登錄檔上限）逐條回報。
pub async fn create(pool: &PgPool, keys: &[String], actor: &str) -> Result<Created, sqlx::Error> {
    let mut out = Created::default();
    for t in all().iter().filter(|t| keys.contains(&t.key)) {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM compliance_rules WHERE template_key = $1)",
        )
        .bind(&t.key)
        .fetch_one(pool)
        .await?;
        if exists {
            out.skipped.push(t.name.clone());
            continue;
        }
        let input = RuleInput {
            name: t.name.clone(),
            description: t.description.clone(),
            kind: t.kind.clone(),
            severity: t.severity.clone(),
            enabled: true,
            params: t.params.clone(),
            include: vec![],
            exclude: vec![],
            template_key: Some(t.key.clone()),
        };
        match admin::create_rule(pool, &input, actor).await {
            Ok(_) => out.created.push(t.name.clone()),
            // 兩個管理員同時建立：唯一索引擋下，當作已存在
            Err(e) if e.downcast_ref::<admin::TemplateExists>().is_some() => {
                out.skipped.push(t.name.clone())
            }
            Err(e) => out.failed.push((t.name.clone(), format!("{e:#}"))),
        }
    }
    Ok(out)
}

/// 已建立過的範本 key
pub async fn used_keys(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT template_key FROM compliance_rules WHERE template_key IS NOT NULL")
        .fetch_all(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_parses_and_keys_are_unique() {
        let all = all();
        assert!(all.len() >= 20, "{}", all.len());
        let mut keys: Vec<&str> = all.iter().map(|t| t.key.as_str()).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), all.len(), "key 重複");
        for t in all {
            crate::compliance::rules::Params::parse(&t.kind, &t.params)
                .unwrap_or_else(|e| panic!("{}: {e}", t.key));
            assert!(
                crate::compliance::rules::Severity::parse(&t.severity).is_some(),
                "{}",
                t.key
            );
            // 出處直接放進 href：必須是單一 https 網址
            assert!(
                t.source.starts_with("https://") && !t.source.contains(char::is_whitespace),
                "{} 出處不是單一網址：{}",
                t.key,
                t.source
            );
        }
    }
}
