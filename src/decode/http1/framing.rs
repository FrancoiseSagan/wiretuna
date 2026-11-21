const MAX_PREVIEW: usize = 256;

pub(super) enum Framing {
    None,
    Fixed(usize),
    Chunked,
    UntilClose,
}

pub(super) struct Body {
    pub consumed: usize,
    pub bytes: usize,
    pub preview: Vec<u8>,
    pub issue: Option<&'static str>,
}

impl Body {
    pub fn empty() -> Self {
        Self {
            consumed: 0,
            bytes: 0,
            preview: Vec::new(),
            issue: None,
        }
    }

    pub fn failed(issue: &'static str) -> Self {
        Self {
            issue: Some(issue),
            ..Self::empty()
        }
    }

    fn take(data: &[u8], limit: usize, issue: Option<&'static str>) -> Self {
        let consumed = limit.min(data.len());
        Self {
            consumed,
            bytes: consumed,
            preview: data[..consumed.min(MAX_PREVIEW)].to_vec(),
            issue,
        }
    }
}

impl Framing {
    pub fn from_headers(
        headers: &[httparse::Header<'_>],
        request: bool,
    ) -> Result<Self, &'static str> {
        let mut content_length = None;
        let mut transfer_encoding = None;
        for header in headers {
            if header.name.eq_ignore_ascii_case("content-length") {
                let values =
                    std::str::from_utf8(header.value).map_err(|_| "Invalid Content-Length.")?;
                for value in values.split(',') {
                    let value = value.trim();
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err("Invalid Content-Length.");
                    }
                    let parsed = value
                        .parse::<usize>()
                        .map_err(|_| "Invalid Content-Length.")?;
                    if content_length
                        .replace(parsed)
                        .is_some_and(|previous| previous != parsed)
                    {
                        return Err("Conflicting Content-Length values.");
                    }
                }
            } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                let value =
                    std::str::from_utf8(header.value).map_err(|_| "Invalid Transfer-Encoding.")?;
                transfer_encoding = Some(value.rsplit(',').next().unwrap_or_default().trim());
            }
        }
        match (content_length, transfer_encoding) {
            (Some(_), Some(_)) => Err("Ambiguous HTTP body framing."),
            (None, Some(encoding)) if encoding.eq_ignore_ascii_case("chunked") => Ok(Self::Chunked),
            (None, Some(_)) if request => Err("Unsupported request transfer coding."),
            (_, Some(_)) => Ok(Self::UntilClose),
            (Some(length), None) => Ok(Self::Fixed(length)),
            (None, None) if request => Ok(Self::None),
            (None, None) => Ok(Self::UntilClose),
        }
    }

    pub fn read(self, bytes: &[u8], finished: bool) -> Body {
        match self {
            Self::None => Body::empty(),
            Self::Fixed(length) => Body::take(
                bytes,
                length,
                (length > bytes.len()).then_some("Body is incomplete."),
            ),
            Self::Chunked => chunks(bytes),
            Self::UntilClose => Body::take(
                bytes,
                bytes.len(),
                (!finished).then_some("Connection close was not observed."),
            ),
        }
    }
}

fn chunks(bytes: &[u8]) -> Body {
    let mut body = Body::empty();
    for _ in 0..4096 {
        let Ok(httparse::Status::Complete((prefix, size))) =
            httparse::parse_chunk_size(&bytes[body.consumed..])
        else {
            body.issue = Some("Incomplete or invalid chunk size.");
            return body;
        };
        body.consumed += prefix;
        if size == 0 {
            let mut slots = [httparse::EMPTY_HEADER; 64];
            if let Ok(httparse::Status::Complete((len, _))) =
                httparse::parse_headers(&bytes[body.consumed..], &mut slots)
            {
                body.consumed += len;
            } else {
                body.issue = Some("Incomplete or invalid chunk trailers.");
            }
            return body;
        }

        let remaining = &bytes[body.consumed..];
        let len = usize::try_from(size).unwrap_or(usize::MAX);
        let captured = len.min(remaining.len());
        body.bytes += captured;
        let preview = captured.min(MAX_PREVIEW - body.preview.len());
        body.preview.extend_from_slice(&remaining[..preview]);
        body.consumed += captured;
        if captured != len || !remaining[len..].starts_with(b"\r\n") {
            body.issue = Some("Incomplete or invalid chunk data.");
            return body;
        }
        body.consumed += 2;
    }
    body.issue = Some("HTTP chunk limit reached.");
    body
}
