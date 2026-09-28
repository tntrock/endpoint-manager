//! 儀表板。

use askama::Template;
use axum::response::Response;

use super::auth::{AdminSession, Nav};
use super::render;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav: Nav,
}

pub async fn page(AdminSession(s): AdminSession) -> Response {
    render(&DashboardPage { nav: Nav::from(&s) })
}
