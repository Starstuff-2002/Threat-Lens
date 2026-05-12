fetch('http://localhost:8000/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: 'aws_key = "AKIA1234567890ABCDEF"' })
}).then(r => r.text()).then(console.log).catch(console.error);
