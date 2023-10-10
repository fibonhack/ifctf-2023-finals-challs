use crate::Context;
use crate::Error;
use base32::Alphabet;
use base64::{engine::general_purpose, Engine as _};
use goldberg::goldberg_string;

/// Show this help menu
#[poise::command(prefix_command)]
pub async fn receive_code(
    ctx: Context<'_>,
    #[description = "send me codes plz >.<"] code: String,
) -> Result<(), Error> {
    {
        let input = general_purpose::STANDARD.decode(code).unwrap();
        let input = String::from_utf8_lossy(input.as_slice());
        let mut buf = String::new();
        let mut good = true;
        let mut right_len = false;
        for i in 0..1024 {
            if i < 64 && i < input.len() {
                if i < 8 {
                    buf += input.chars().nth(i).unwrap().to_string().as_str();
                    if i % 4 == 3 {
                        if i < 5 {
                            if buf != String::from(goldberg_string!("ifct")) {
                                good = false;
                            }
                        } else if i < 15 {
                            if buf != String::from(goldberg_string!("f{fm")) {
                                good = false;
                            }
                        } else {
                            good = false;
                        }

                        buf = String::new();
                    }
                } else if i < 16 {
                    buf += input.chars().nth(i).unwrap().to_string().as_str();
                    if i == 15 {
                        let enc = general_purpose::STANDARD.encode(buf);

                        if enc != String::from(goldberg_string!("bF93aHlfNG0=")) {
                            good = false;
                        }
                        buf = String::new();
                    }
                } else if i < 41 {
                    buf += input.chars().nth(i).unwrap().to_string().as_str();
                    if i == 40 {
                        buf.chars().enumerate().for_each(|(j, c)| {
                            if c as u64
                                ^ String::from(goldberg_string!("kekkus_maximus_meridius69"))
                                    .chars()
                                    .nth(j)
                                    .unwrap() as u64
                                != [
                                    0x34, 0x54, 0x34, 0x03, 0x46, 0x01, 0x6c, 0x32, 0x55, 0x4f,
                                    0x36, 0x5c, 0x45, 0x2c, 0x6b, 0x00, 0x3a, 0x05, 0x1b, 0x55,
                                    0x5e, 0x44, 0x1d, 0x00, 0x66,
                                ][j]
                            {
                                good = false
                            };
                        });
                        buf = String::new();
                    }
                } else if i < 45 {
                    println!("{buf}");
                    buf += input.chars().nth(i).unwrap().to_string().as_str();
                    if i == 60 {
                        let enc =
                            base32::encode(Alphabet::Crockford, Vec::<u8>::from(buf).as_slice());

                        if enc != String::from(goldberg_string!("G5UDCNK7OIZXMX3QNR5F6NJTNY======"))
                        {
                            good = false;
                        }

                        buf = String::new();
                    }
                } else if i < 61 {
                    if i == 63 {
                        buf.chars().enumerate().for_each(|(j, c)| {
                            if c as u64 ^ "f33t".chars().nth(j).unwrap() as u64
                                != [0x02, 0x3a, 0x0d, 0x47][j]
                            {
                                good = false
                            };
                        });
                        buf = String::new();
                    }
                } else if i < 69 {
                    if i == 61 {
                        if "l" != input.chars().nth(i).unwrap().to_string() {
                            good = false;
                        }
                    } else if i == 62 {
                        if "p" != input.chars().nth(i).unwrap().to_string() {
                            good = false;
                        }
                    } else if i == 63 {
                        right_len = input.len() < 65;
                        if "}" != input.chars().nth(i).unwrap().to_string() {
                            good = false;
                        }
                    } else {
                        good = false;
                    }
                }
            } else {
                buf += input
                    .chars()
                    .nth(i % input.len())
                    .unwrap_or('a')
                    .to_string()
                    .as_str();
                if i % 64 == 0 {
                    let enc = general_purpose::STANDARD.encode(buf.clone());
                    if enc != "idkfeetIguess" {
                        buf = String::new();
                    }
                }
            }
        }

        if good && right_len {
            ctx.send(|m| {
                m.reply(true).embed(|embed| {
                    embed.title("lgtm gg");
                    embed
                })
            })
            .await?;
            println!("good");
        } else {
            ctx.send(|m| {
                m.reply(true).embed(|embed| {
                    embed.title("try sending me feet next time, this didn't look good at all");
                    embed
                })
            })
            .await?;
            println!("not good");
        }
        Ok(())
    }
}
