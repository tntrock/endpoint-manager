//! 伺服器產生的 SVG 圖表座標。顏色由樣板的 class 決定（CSS 變數），這裡只算位置。

use time::Date;

/// 趨勢圖的畫布（viewBox）
pub const W: f64 = 640.0;
pub const H: f64 = 210.0;
const LEFT: f64 = 44.0;
const RIGHT: f64 = 630.0;
const TOP: f64 = 20.0;
const BOTTOM: f64 = 170.0;

pub struct Series {
    /// CSS class（決定顏色與線型）
    pub class: &'static str,
    /// `<polyline points>`
    pub points: String,
    /// 最後一個點
    pub last: (f64, f64),
}

pub struct LineChart {
    pub series: Vec<Series>,
    /// (y, 標籤)
    pub y_ticks: Vec<(f64, String)>,
    /// (x, 標籤)
    pub x_labels: Vec<(f64, String)>,
}

/// 刻度的間距：1、2、5 乘以 10 的次方，讓 4 格能涵蓋 `max`
fn nice_step(max: i64) -> i64 {
    let raw = (max.max(1) as f64 / 4.0).ceil() as i64;
    let mut mag = 1;
    while mag * 10 <= raw {
        mag *= 10;
    }
    [1, 2, 5, 10]
        .into_iter()
        .map(|m| m * mag)
        .find(|s| *s >= raw)
        .unwrap_or(10 * mag)
}

fn fmt(v: f64) -> String {
    let s = format!("{v:.1}");
    s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
}

/// `start..=end` 期間的折線圖；每條線是 (class, [(日期, 值)])，沒有資料的日子不補值。
/// 任何一條線少於 2 個點時回 None
pub fn line_chart(
    start: Date,
    end: Date,
    lines: &[(&'static str, Vec<(Date, i64)>)],
) -> Option<LineChart> {
    if lines.is_empty() || lines.iter().any(|(_, pts)| pts.len() < 2) {
        return None;
    }
    let span = (end - start).whole_days().max(1) as f64;
    let max = lines
        .iter()
        .flat_map(|(_, pts)| pts.iter().map(|p| p.1))
        .max()
        .unwrap_or(0);
    let step = nice_step(max);
    let top = (step * 4) as f64;
    let x = |d: Date| LEFT + (d - start).whole_days() as f64 / span * (RIGHT - LEFT);
    let y = |v: i64| BOTTOM - v.max(0) as f64 / top * (BOTTOM - TOP);
    let series = lines
        .iter()
        .map(|(class, pts)| {
            let coords: Vec<(f64, f64)> = pts.iter().map(|(d, v)| (x(*d), y(*v))).collect();
            Series {
                class,
                points: coords
                    .iter()
                    .map(|(a, b)| format!("{},{}", fmt(*a), fmt(*b)))
                    .collect::<Vec<_>>()
                    .join(" "),
                last: *coords.last().expect("at least two points"),
            }
        })
        .collect();
    let y_ticks = (0..=4)
        .map(|i| (y(step * i), (step * i).to_string()))
        .collect();
    // 最多 5 個日期標籤，平均分布，頭尾一定有
    let days = (end - start).whole_days();
    let n = days.clamp(1, 4);
    let x_labels = (0..=n)
        .map(|i| {
            let d = start + time::Duration::days(days * i / n);
            (x(d), format!("{}/{}", u8::from(d.month()), d.day()))
        })
        .collect();
    Some(LineChart {
        series,
        y_ticks,
        x_labels,
    })
}

/// 迷你折線（viewBox 0 0 96 32）；少於 2 個點時回 None
pub fn sparkline(values: &[f64]) -> Option<String> {
    if values.len() < 2 {
        return None;
    }
    let (lo, hi) = values
        .iter()
        .fold((f64::MAX, f64::MIN), |(a, b), v| (a.min(*v), b.max(*v)));
    let range = if hi > lo { hi - lo } else { 1.0 };
    let last = (values.len() - 1) as f64;
    Some(
        values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let x = i as f64 / last * 96.0;
                // 全部相同時畫在中間
                let y = if hi > lo {
                    30.0 - (v - lo) / range * 28.0
                } else {
                    16.0
                };
                format!("{},{}", fmt(x), fmt(y))
            })
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// 環形圖（r = 26）的 `stroke-dasharray`
pub fn ring_dash(pct: f64) -> String {
    let c = 2.0 * std::f64::consts::PI * 26.0;
    format!("{} {}", fmt(c * pct.clamp(0.0, 100.0) / 100.0), fmt(c))
}

/// 堆疊長條（viewBox 寬 100）：每段 (x, 寬度)
pub fn stack(parts: &[i64]) -> Vec<(f64, f64)> {
    let total: i64 = parts.iter().map(|p| (*p).max(0)).sum();
    let mut x = 0.0;
    parts
        .iter()
        .map(|p| {
            let w = if total > 0 {
                (*p).max(0) as f64 * 100.0 / total as f64
            } else {
                0.0
            };
            let seg = ((x * 10.0_f64).round() / 10.0, (w * 10.0_f64).round() / 10.0);
            x += w;
            seg
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::date;

    #[test]
    fn steps_are_round() {
        assert_eq!(nice_step(0), 1);
        assert_eq!(nice_step(4), 1);
        assert_eq!(nice_step(5), 2);
        assert_eq!(nice_step(40), 10);
        assert_eq!(nice_step(41), 20);
        assert_eq!(nice_step(30_000), 10_000);
        assert_eq!(nice_step(7_000), 2_000);
    }

    #[test]
    fn line_chart_maps_dates_and_values() {
        let start = date!(2026 - 11 - 01);
        let end = date!(2026 - 11 - 30);
        let c = line_chart(
            start,
            end,
            &[
                ("a", vec![(start, 0), (end, 8)]),
                ("b", vec![(date!(2026 - 11 - 15), 2), (end, 4)]),
            ],
        )
        .unwrap();
        assert_eq!(c.series[0].points, "44,170 630,20");
        assert_eq!(c.series[0].last, (630.0, 20.0));
        // 11/15 是第 14 天
        assert!(c.series[1].points.starts_with("326.9,132.5 "));
        assert_eq!(c.y_ticks.len(), 5);
        assert_eq!(c.y_ticks[4], (20.0, "8".into()));
        assert_eq!(c.x_labels.len(), 5);
        assert_eq!(c.x_labels[0].1, "11/1");
        assert_eq!(c.x_labels[4], (630.0, "11/30".into()));
    }

    #[test]
    fn line_chart_needs_two_points() {
        let d = date!(2026 - 11 - 21);
        assert!(line_chart(d, d, &[("a", vec![(d, 1)])]).is_none());
        assert!(line_chart(d, d, &[]).is_none());
        // 同一天兩個點不會除以零；只有一天時只有頭尾兩個標籤
        let c = line_chart(d, d, &[("a", vec![(d, 1), (d, 2)])]).unwrap();
        assert_eq!(c.x_labels.len(), 2);
    }

    #[test]
    fn sparkline_scales_and_handles_flat() {
        assert_eq!(sparkline(&[1.0]), None);
        assert_eq!(sparkline(&[0.0, 10.0]).unwrap(), "0,30 96,2");
        assert_eq!(sparkline(&[5.0, 5.0, 5.0]).unwrap(), "0,16 48,16 96,16");
    }

    #[test]
    fn ring_and_stack() {
        assert_eq!(ring_dash(0.0), "0 163.4");
        assert_eq!(ring_dash(100.0), "163.4 163.4");
        assert_eq!(ring_dash(150.0), "163.4 163.4");
        assert_eq!(
            stack(&[1, 1, 2]),
            vec![(0.0, 25.0), (25.0, 25.0), (50.0, 50.0)]
        );
        assert_eq!(stack(&[0, 0]), vec![(0.0, 0.0), (0.0, 0.0)]);
    }
}
