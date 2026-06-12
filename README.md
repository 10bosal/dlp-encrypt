# DLP Encrypt

민감 문서를 **AES-GCM**으로 암호화하는 CLI/라이브러리입니다.  
암호화 포맷은 [dlp-mcp](../dlp-mcp) 복호화 서버와 호환됩니다.

## 암호화 포맷

- **알고리즘**: AES-GCM (키 길이: 128/192/256-bit)
- **기본 파일 포맷**: `[12-byte nonce][ciphertext + 16-byte auth tag]`
- 외부 nonce 사용 시 `--no-embed-nonce` 옵션으로 nonce를 분리

## 설치

```bash
cd work/dlp-encrypt
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## 사용법

```bash
# 키 생성 (dlp-mcp의 DECRYPTION_KEY_HEX와 동일한 값 사용)
export ENCRYPTION_KEY_HEX=$(openssl rand -hex 32)

# 파일 암호화
dlp-encrypt sample.txt

# 출력 경로 지정 + MCP용 base64 출력
dlp-encrypt sample.pdf --mime-type application/pdf -o sample.pdf.enc --print-b64
```

## 환경 변수

| 변수 | 필수 | 설명 |
|------|------|------|
| `ENCRYPTION_KEY_HEX` | ✅ | AES 키 (hex). `DECRYPTION_KEY_HEX`도 인식 |
| `--key-hex` | | CLI에서 키를 직접 지정 (환경 변수 대신) |

## Python API

```python
from pathlib import Path
from dlp_encrypt import encrypt_file

result = encrypt_file(Path("report.docx"), key=bytes.fromhex("..."))
print(result.output_path, len(result.payload))
```

## dlp-mcp 연동

1. `dlp-encrypt`로 문서 암호화
2. 암호화 파일을 ChatGPT에 업로드
3. ChatGPT가 `dlp-mcp`의 `decrypt_file` 도구로 복호화 후 추론

## 보안 참고

- 암호화 키는 코드/저장소에 포함하지 마세요.
- `dlp-mcp` 서버의 `DECRYPTION_KEY_HEX`와 클라이언트의 `ENCRYPTION_KEY_HEX`는 동일해야 합니다.
