use axum::{
    extract::Path,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};

pub(super) async fn index() -> Html<&'static str> {
    Html(include_str!("../../web/index.html"))
}

pub(super) async fn asset(Path(name): Path<String>) -> Response {
    let script = "text/javascript; charset=utf-8";
    let (content_type, source) = match name.as_str() {
        "app.css" => ("text/css; charset=utf-8", include_str!("../../web/app.css")),
        "api.js" => (script, include_str!("../../web/modules/api.js")),
        "details.js" => (script, include_str!("../../web/modules/details.js")),
        "dom.js" => (script, include_str!("../../web/modules/dom.js")),
        "main.js" => (script, include_str!("../../web/modules/main.js")),
        "packets.js" => (script, include_str!("../../web/modules/packets.js")),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    ([(header::CONTENT_TYPE, content_type)], source).into_response()
}
