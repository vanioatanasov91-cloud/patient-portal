"""Generated PDF controls; harmless EICAR only, no patient files."""
import io
from clamd_preflight import EICAR

def pdf_bytes(label):
    from reportlab.pdfgen import canvas
    body=io.BytesIO();pdf=canvas.Canvas(body);pdf.drawString(60,700,label);pdf.save();return body.getvalue()


def eicar_pdf():
    # A real PDF with an embedded 68-byte harmless EICAR file. Exact xref/lengths
    # avoid confusing PDF container rejection with actual antivirus rejection.
    content=b'BT /F1 12 Tf 50 700 Td (SYNTHETIC ANTIVIRUS CONTROL) Tj ET\n'
    objects=[
        b'<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(synthetic-eicar.com) 5 0 R] >> >> >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 6 0 R >> >> /Contents 4 0 R >>',
        b'<< /Length '+str(len(content)).encode()+b' >>\nstream\n'+content+b'endstream',
        b'<< /Type /Filespec /F (synthetic-eicar.com) /EF << /F 7 0 R >> >>',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        b'<< /Type /EmbeddedFile /Length '+str(len(EICAR)).encode()+b' >>\nstream\n'+EICAR+b'\nendstream',
    ]
    body=bytearray(b'%PDF-1.4\n');offsets=[0]
    for number,obj in enumerate(objects,1):
        offsets.append(len(body));body.extend(f'{number} 0 obj\n'.encode()+obj+b'\nendobj\n')
    xref=len(body);body.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:body.extend(f'{offset:010d} 00000 n \n'.encode())
    body.extend(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(body)

