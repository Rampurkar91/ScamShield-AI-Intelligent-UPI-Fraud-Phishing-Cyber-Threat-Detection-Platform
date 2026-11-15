"""Local QR inspection and optional OCR; never fetch decoded links or persist content."""
from io import BytesIO
import shutil
import subprocess
from urllib.parse import urlsplit
from PIL import Image
import zxingcpp
from .scanners import analyze, score_indicators


def analyze_image(data: bytes):
    indicators, limitations = [], []
    findings = []
    with Image.open(BytesIO(data)) as image:
        image.load()
        rgb = image.convert('RGB')
        try:
            codes = zxingcpp.read_barcodes(rgb, formats=zxingcpp.BarcodeFormat.QRCode)
            for code in codes[:10]:
                content = code.text[:30000]
                if content.lower().startswith(('http://', 'https://')):
                    findings.append(analyze('url', content))
                elif urlsplit(content).scheme.lower() == 'upi':
                    indicators.append({'name': 'UPI payment QR code', 'severity': 'medium', 'explanation': 'A QR code can initiate a payment. Confirm the recipient and amount in your payment app; scanning a QR code does not receive money.'})
                elif content:
                    findings.append(analyze('message', content))
            if len(codes) > 10:
                limitations.append('Only the first 10 QR codes were analyzed.')
        except Exception:
            limitations.append('QR decoding failed; the image may contain unread QR codes.')
            codes = []
        ocr_text = ''
        if shutil.which('tesseract'):
            try:
                # Send a normalized image through stdin; no untrusted filename or shell.
                normalized = BytesIO()
                rgb.save(normalized, format='PNG')
                proc = subprocess.run(['tesseract', 'stdin', 'stdout', '-l', 'eng'], input=normalized.getvalue(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=True)
                ocr_text = proc.stdout.decode('utf-8', errors='replace')[:30000].strip()
                if ocr_text:
                    findings.append(analyze('message', ocr_text))
                else:
                    limitations.append('OCR found no readable text; text may have been missed.')
                limitations.append('OCR is limited to English and may miss or misread text.')
            except (subprocess.SubprocessError, OSError):
                limitations.append('OCR failed or timed out; image text was not analyzed.')
        else:
            limitations.append('OCR is unavailable; image text was not analyzed.')
    for finding in findings:
        indicators.extend(finding['indicators'])
        limitations.extend(finding['limitations'])
    limitations.append('QR detection can miss obscured or damaged codes; no URLs were visited.')
    if not codes:
        limitations.append('No QR code was decoded; this does not prove one is absent.')
    result = score_indicators(indicators, limitations, unknown=not codes and not ocr_text)
    result['checks'] = {'qr': 'completed' if not any(x.startswith('QR decoding failed') for x in limitations) else 'failed', 'ocr': 'completed' if ocr_text else ('unavailable' if not shutil.which('tesseract') else 'no_text_or_failed')}
    return result
