//! Helpers for building chat content parts from images and audio.
//!
//! ```rust,ignore
//! use tinfoil::multimodal::{ImageUrlExt, InputAudioExt};
//! use tinfoil::chat::{ImageUrl, InputAudio};
//!
//! let img = ImageUrl::from_path("test.jpg")?;
//! let audio = InputAudio::from_path("test.mp3")?;
//! ```

use std::io;
use std::path::Path;

use async_openai::types::chat::{ImageDetail, ImageUrl, InputAudio, InputAudioFormat};
use base64::Engine;

/// Constructors for `ImageUrl` data URLs with `detail: auto`.
pub trait ImageUrlExt {
    /// Build an `ImageUrl` from a file on disk. Mime type is inferred from
    /// the extension (`.jpg` -> `image/jpeg`, etc.).
    fn from_path(path: impl AsRef<Path>) -> io::Result<ImageUrl>;

    /// Build an `ImageUrl` from in-memory bytes plus an explicit mime type
    /// (for example `"image/png"`).
    fn from_bytes(bytes: &[u8], mime_type: &str) -> ImageUrl;

    /// Build an `ImageUrl` from a base64 string and mime type. Handy when
    /// the bytes have already been encoded upstream.
    fn from_base64(base64_data: impl Into<String>, mime_type: &str) -> ImageUrl;
}

impl ImageUrlExt for ImageUrl {
    fn from_path(path: impl AsRef<Path>) -> io::Result<ImageUrl> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let mime_type = guess_image_mime(path);
        Ok(Self::from_bytes(&bytes, &mime_type))
    }

    fn from_bytes(bytes: &[u8], mime_type: &str) -> ImageUrl {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        Self::from_base64(encoded, mime_type)
    }

    fn from_base64(base64_data: impl Into<String>, mime_type: &str) -> ImageUrl {
        ImageUrl {
            url: format!("data:{};base64,{}", mime_type, base64_data.into()),
            // Avoid serialising `detail` as null, which the router rejects.
            detail: Some(ImageDetail::Auto),
        }
    }
}

/// Constructors for [`InputAudio`].
pub trait InputAudioExt {
    /// Build an `InputAudio` from a file on disk. The format is inferred
    /// from the extension.
    fn from_path(path: impl AsRef<Path>) -> io::Result<InputAudio>;

    /// Build an `InputAudio` from in-memory bytes and an explicit format.
    fn from_bytes(bytes: &[u8], format: InputAudioFormat) -> InputAudio;
}

impl InputAudioExt for InputAudio {
    fn from_path(path: impl AsRef<Path>) -> io::Result<InputAudio> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let format = guess_audio_format(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Unsupported or unrecognised audio extension for {}",
                    path.display()
                ),
            )
        })?;
        Ok(Self::from_bytes(&bytes, format))
    }

    fn from_bytes(bytes: &[u8], format: InputAudioFormat) -> InputAudio {
        InputAudio {
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
            format,
        }
    }
}

fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
}

fn guess_image_mime(path: &Path) -> String {
    match extension_lower(path).as_deref() {
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("bmp") => "image/bmp",
        _ => "image/jpeg",
    }
    .to_string()
}

fn guess_audio_format(path: &Path) -> Option<InputAudioFormat> {
    match extension_lower(path).as_deref() {
        Some("mp3") => Some(InputAudioFormat::Mp3),
        Some("wav") => Some(InputAudioFormat::Wav),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_url_from_bytes_uses_auto_detail_and_data_url() {
        let url = ImageUrl::from_bytes(b"abc", "image/png");
        assert_eq!(url.detail, Some(ImageDetail::Auto));
        assert!(url.url.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn image_url_mime_inferred_from_extension() {
        assert_eq!(guess_image_mime(Path::new("a.jpg")), "image/jpeg");
        assert_eq!(guess_image_mime(Path::new("a.JPEG")), "image/jpeg");
        assert_eq!(guess_image_mime(Path::new("a.png")), "image/png");
        assert_eq!(guess_image_mime(Path::new("a.unknown")), "image/jpeg");
    }

    #[test]
    fn input_audio_from_bytes_base64_encodes() {
        let audio = InputAudio::from_bytes(b"abc", InputAudioFormat::Mp3);
        assert_eq!(audio.data, "YWJj");
        assert!(matches!(audio.format, InputAudioFormat::Mp3));
    }

    #[test]
    fn audio_format_inferred_from_extension() {
        assert!(matches!(
            guess_audio_format(Path::new("a.mp3")),
            Some(InputAudioFormat::Mp3)
        ));
        assert!(matches!(
            guess_audio_format(Path::new("a.WAV")),
            Some(InputAudioFormat::Wav)
        ));
        assert!(guess_audio_format(Path::new("a.flac")).is_none());
    }
}
