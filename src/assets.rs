pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    match path {
        "/" | "/index.html" => Some((
            "text/html; charset=utf-8",
            include_bytes!("../ui/dist/index.html"),
        )),
        "/app.js" => Some((
            "text/javascript; charset=utf-8",
            include_bytes!("../ui/dist/app.js"),
        )),
        "/app.css" => Some((
            "text/css; charset=utf-8",
            include_bytes!("../ui/dist/app.css"),
        )),
        _ => None,
    }
}
