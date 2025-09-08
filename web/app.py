from flask import Flask
from datetime import datetime, timedelta, timezone

# Flask 앱 생성
app = Flask(__name__)

# Windows XP 테마의 HTML과 CSS
html_content = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Project Guardian</title>
    <style>
        body {
            background-color: #3A6EA5; /* 윈도우 XP 바탕화면 파란색 */
            font-family: Tahoma, Geneva, sans-serif;
            font-size: 12px;
            margin: 0;
            padding: 0;
            overflow: hidden; /* 스크롤바 제거 */
        }
        .window {
            width: 600px;
            height: 400px;
            border: 2px solid #0058E1;
            border-radius: 8px 8px 0 0;
            background-color: #ECE9D8;
            box-shadow: 5px 5px 15px rgba(0,0,0,0.5);
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            display: flex;
            flex-direction: column;
        }
        .title-bar {
            background: linear-gradient(to bottom, #0058E1, #3A85E1);
            color: white;
            font-weight: bold;
            padding: 5px 10px;
            border-top-left-radius: 5px;
            border-top-right-radius: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: move;
        }
        .title-bar-buttons span {
            display: inline-block;
            width: 20px;
            height: 20px;
            margin-left: 2px;
            background-color: #D64F34;
            color: white;
            text-align: center;
            line-height: 20px;
            border: 1px solid white;
            font-family: 'Courier New', Courier, monospace;
        }
        .content {
            padding: 20px;
            flex-grow: 1;
            color: #000;
        }
        .content h1 {
            font-size: 24px;
            color: #0058E1;
        }
        .taskbar {
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 30px;
            background: linear-gradient(to bottom, #245EDC, #3A85E1);
            border-top: 1px solid #66A3FF;
            display: flex;
            align-items: center;
        }
        .start-button {
            background: linear-gradient(to bottom, #72BE4A, #55A82B);
            color: white;
            font-weight: bold;
            font-size: 16px;
            border: 2px outset #55A82B;
            border-radius: 10px 10px 0 0;
            padding: 2px 20px;
            margin-left: 5px;
            font-style: italic;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="window">
        <div class="title-bar">
            <span>Project Guardian - Microsoft Azure</span>
            <div class="title-bar-buttons">
                <span>_</span><span>☐</span><span>X</span>
            </div>
        </div>
        <div class="content">
            <h1>Deployment Successful!</h1>
            <p><strong>Project Cherubim</strong> is now running on Azure App Service.</p>
            <p>Your Python Flask application has been successfully deployed via GitHub Actions CI/CD pipeline.</p>
            <p>Current Time (KST): {{ current_time }}</p>
        </div>
    </div>
    <div class="taskbar">
        <div class="start-button">start</div>
    </div>
</body>
</html>
"""

# UTC 시간을 KST로 변환하기 위한 설정
KST = timezone(timedelta(hours=9))

@app.route('/')
def home():
    # 현재 시간을 KST로 포맷팅
    kst_time_str = datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S')
    # HTML 템플릿에 시간 변수를 전달
    return html_content.replace('{{ current_time }}', kst_time_str)

if __name__ == '__main__':
    # 로컬 테스트용 서버 실행
    app.run(debug=True)