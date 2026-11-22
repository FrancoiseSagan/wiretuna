//! Typed display filters. Input and nesting are bounded before evaluation.

use std::{fmt, net::IpAddr};

use crate::decode::{Protocol, Summary};

#[derive(Debug)]
pub struct Filter(Expr);

#[derive(Debug)]
enum Expr {
    All,
    Protocol(Protocol),
    Ip(Field, IpAddr),
    Port(Field, u16),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug)]
enum Field {
    Source,
    Destination,
    SourcePort(Protocol),
    DestinationPort(Protocol),
}

impl Expr {
    fn matches(&self, summary: &Summary) -> bool {
        match self {
            Self::All => true,
            Self::Protocol(protocol) => summary.has(*protocol),
            Self::Ip(Field::Source, value) => summary.source == Some(*value),
            Self::Ip(Field::Destination, value) => summary.destination == Some(*value),
            Self::Port(Field::SourcePort(protocol), port) => {
                summary.has(*protocol) && summary.source_port == Some(*port)
            }
            Self::Port(Field::DestinationPort(protocol), port) => {
                summary.has(*protocol) && summary.destination_port == Some(*port)
            }
            Self::Not(value) => !value.matches(summary),
            Self::And(left, right) => left.matches(summary) && right.matches(summary),
            Self::Or(left, right) => left.matches(summary) || right.matches(summary),
            _ => unreachable!("parser associates field names with their value types"),
        }
    }
}

impl Filter {
    pub fn parse(input: &str) -> Result<Self, FilterError> {
        if input.len() > 512 {
            return Err(FilterError {
                offset: 512,
                message: "filter exceeds 512 bytes",
            });
        }
        if input.trim().is_empty() {
            return Ok(Self(Expr::All));
        }
        let mut parser = Parser { input, cursor: 0 };
        let expression = parser.or(0)?;
        if !parser.remaining().is_empty() {
            return Err(parser.error("unexpected filter text"));
        }
        Ok(Self(expression))
    }

    pub fn matches(&self, summary: &Summary) -> bool {
        self.0.matches(summary)
    }
}

#[derive(Debug)]
pub struct FilterError {
    pub offset: usize,
    pub message: &'static str,
}

impl fmt::Display for FilterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "filter at byte {}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for FilterError {}

struct Parser<'a> {
    input: &'a str,
    cursor: usize,
}

impl<'a> Parser<'a> {
    fn remaining(&mut self) -> &'a str {
        let rest = &self.input[self.cursor..];
        let trimmed = rest.trim_start();
        self.cursor += rest.len() - trimmed.len();
        trimmed
    }

    fn eat(&mut self, token: &str) -> bool {
        if self.remaining().starts_with(token) {
            self.cursor += token.len();
            return true;
        }
        false
    }

    fn word(&mut self) -> &'a str {
        let input = self.remaining();
        let end = input
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':')))
            .unwrap_or(input.len());
        self.cursor += end;
        &input[..end]
    }

    fn error(&self, message: &'static str) -> FilterError {
        FilterError {
            offset: self.cursor,
            message,
        }
    }

    fn or(&mut self, depth: usize) -> Result<Expr, FilterError> {
        let mut left = self.and(depth)?;
        while self.eat("||") {
            left = Expr::Or(Box::new(left), Box::new(self.and(depth)?));
        }
        Ok(left)
    }

    fn and(&mut self, depth: usize) -> Result<Expr, FilterError> {
        let mut left = self.term(depth)?;
        while self.eat("&&") {
            left = Expr::And(Box::new(left), Box::new(self.term(depth)?));
        }
        Ok(left)
    }

    fn term(&mut self, depth: usize) -> Result<Expr, FilterError> {
        if depth >= 16 {
            return Err(self.error("filter nesting limit reached"));
        }
        if self.eat("!") {
            return Ok(Expr::Not(Box::new(self.term(depth + 1)?)));
        }
        if self.eat("(") {
            let expr = self.or(depth + 1)?;
            if !self.eat(")") {
                return Err(self.error("expected closing parenthesis"));
            }
            return Ok(expr);
        }
        self.remaining();
        let offset = self.cursor;
        let word = self.word();
        let protocol = match word {
            "eth" => Some(Protocol::Ethernet),
            "vlan" => Some(Protocol::Vlan),
            "arp" => Some(Protocol::Arp),
            "ip" => Some(Protocol::Ipv4),
            "ipv6" => Some(Protocol::Ipv6),
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            "icmpv6" => Some(Protocol::Icmpv6),
            "dns" => Some(Protocol::Dns),
            "quic" => Some(Protocol::Quic),
            _ => None,
        };
        if let Some(protocol) = protocol {
            return Ok(Expr::Protocol(protocol));
        }
        let field = match word {
            "ip.src" | "ipv6.src" => Field::Source,
            "ip.dst" | "ipv6.dst" => Field::Destination,
            "tcp.srcport" => Field::SourcePort(Protocol::Tcp),
            "tcp.dstport" => Field::DestinationPort(Protocol::Tcp),
            "udp.srcport" => Field::SourcePort(Protocol::Udp),
            "udp.dstport" => Field::DestinationPort(Protocol::Udp),
            _ => {
                return Err(FilterError {
                    offset,
                    message: "expected a known protocol or field",
                });
            }
        };
        if !self.eat("==") {
            return Err(self.error("expected =="));
        }
        self.remaining();
        let offset = self.cursor;
        let value = self.word();
        match field {
            Field::Source | Field::Destination => {
                let address: IpAddr = value.parse().map_err(|_| FilterError {
                    offset,
                    message: "expected an IP address",
                })?;
                if address.is_ipv6() != word.starts_with("ipv6.") {
                    return Err(FilterError {
                        offset,
                        message: "address family does not match the field",
                    });
                }
                Ok(Expr::Ip(field, address))
            }
            Field::SourcePort(_) | Field::DestinationPort(_) => {
                let port = value.parse().map_err(|_| FilterError {
                    offset,
                    message: "expected a port from 0 to 65535",
                })?;
                Ok(Expr::Port(field, port))
            }
        }
    }
}
