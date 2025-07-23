// 필요한 모듈 설치 전제: npm install express sqlite3 crypto cors body-parser ejs fs

const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const db = new sqlite3.Database('./keys.db'); // SQLite 데이터베이스 파일
const PORT = process.env.PORT || 4000; // 환경 변수 PORT가 없으면 4000 사용

// --- 초기 설정 및 DB 준비 ---
db.serialize(() => {
  // keys 테이블 생성: 암호화/복호화에 사용될 키들을 저장
  db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL UNIQUE
  )`);
  // config 테이블 생성: 관리자 비밀번호 등 설정 정보 저장
  db.run(`CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  // 초기 관리자 비밀번호 설정 (처음 1회 실행 후 필요에 따라 삭제 또는 수정)
  // 'your-password'를 안전한 비밀번호로 변경하세요.
  db.run(`INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)`, [
    'admin_pw', crypto.createHash('sha256').update('your-password').digest('hex')
  ], (err) => {
    if (err) {
      console.error('관리자 비밀번호 초기 설정 오류:', err.message);
    } else {
      console.log('관리자 비밀번호 초기 설정 완료 (이미 존재하면 건너뜀)');
    }
  });
});

app.use(cors()); // CORS 활성화
app.use(bodyParser.json()); // JSON 형식 요청 본문 파싱
app.use(bodyParser.urlencoded({ extended: true })); // URL-encoded 형식 요청 본문 파싱
app.use(express.static('public')); // 'public' 폴더 정적 파일 호스팅
app.set('view engine', 'ejs'); // 뷰 엔진을 EJS로 설정
app.set('views', path.join(__dirname, 'views')); // 'views' 폴더에서 EJS 템플릿 탐색

// 서버 시작 전 키를 재생성하는 비동기 즉시 실행 함수
// 서버가 시작될 때마다 키를 새로 생성하고 콘솔에 출력합니다.
(async () => {
  console.log('서버 시작 중: 키 재생성을 시작합니다.');
  await regenKeys('main'); // 'main' 그룹의 키 재생성 및 저장
  console.log('키 재생성 완료. 서버를 시작합니다.');
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
})();

// 특정 동작을 로그 파일에 기록하는 함수
function logAction(action, details) {
  const log = `[${new Date().toISOString()}] ${action}: ${details}\n`;
  fs.appendFileSync('logs.txt', log); // 동기 방식으로 로그 파일에 추가
}

// --- 암호화/복호화 함수 ---
// AES-256-CBC 암호화 함수
function aesEncrypt(text, key) {
  const iv = crypto.randomBytes(16); // 16바이트(128비트) IV 생성
  // Buffer.from(key, 'hex')로 키를 16진수 문자열에서 버퍼로 변환
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex'); // 텍스트를 암호화
  encrypted += cipher.final('hex'); // 최종 블록 처리
  return iv.toString('hex') + ':' + encrypted; // IV와 암호화된 데이터를 콜론으로 연결하여 반환
}

// AES-256-CBC 복호화 함수
function aesDecrypt(data, key) {
  const [ivHex, encrypted] = data.split(':'); // IV와 암호화된 데이터를 분리
  // Buffer.from(key, 'hex')로 키를, Buffer.from(ivHex, 'hex')로 IV를 버퍼로 변환
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(ivHex, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8'); // 암호화된 데이터를 복호화
  decrypted += decipher.final('utf8'); // 최종 블록 처리
  return decrypted; // 복호화된 텍스트 반환
}

// 키를 재생성하는 비동기 함수
async function regenKeys(group = 'main') {
  await new Promise((resolve, reject) => {
    db.serialize(() => {
      // 기존 키들을 삭제 (해당 그룹에 속하는 키만)
      db.run(`DELETE FROM keys WHERE type LIKE ?`, [`${group}_%`], (err) => {
        if (err) {
          console.error(`Error deleting existing keys for group ${group}:`, err.message);
          return reject(err);
        }

        const mainKey = crypto.randomBytes(32).toString('hex'); // 256비트(32바이트) 메인 키 생성
        db.run(`INSERT INTO keys (type, value) VALUES (?, ?)`, [`${group}_main`, mainKey], (err) => {
          if (err) console.error(`Error inserting ${group}_main key:`, err.message);
          console.log(`[KEY REGEN] ${group}_main: ${mainKey}`);
          let logMsg = `[KEY REGEN] ${group}_main: ${mainKey}\n`;

          // 10개의 공개 키(pub) 생성
          for (let i = 0; i < 10; i++) {
            const pubKey = crypto.randomBytes(32).toString('hex'); // 256비트(32바이트) 공개 키 생성
            db.run(`INSERT INTO keys (type, value) VALUES (?, ?)`, [`${group}_pub_${i}`, pubKey], (err) => {
              if (err) console.error(`Error inserting ${group}_pub_${i} key:`, err.message);
              console.log(`${group}_pub_${i}: ${pubKey}`);
              logMsg += `${group}_pub_${i}: ${pubKey}\n`;
            });
          }

          logAction('KEY_REGEN', logMsg); // 키 재생성 로그 기록
          resolve(); // Promise 완료
        });
      });
    });
  });
}

// 데이터베이스에서 키들을 가져오는 함수
function getKeys(group, callback) {
  db.all(`SELECT * FROM keys WHERE type LIKE ?`, [`${group}_%`], (err, rows) => {
    if (err) {
      console.error(`Error getting keys for group ${group}:`, err.message);
      return callback({ main: '', pub: [] });
    }
    // pub 키를 인덱스 순서대로 정확하게 저장하기 위해 배열 초기화
    const out = { main: '', pub: Array(10).fill(null) };
    rows.forEach(row => {
      if (row.type === `${group}_main`) {
        out.main = row.value;
      } else if (row.type.startsWith(`${group}_pub_`)) {
        const index = parseInt(row.type.replace(`${group}_pub_`, ''), 10);
        if (!isNaN(index) && index >= 0 && index < 10) {
          out.pub[index] = row.value; // 해당 인덱스에 키 값 저장
        }
      }
    });
    callback(out);
  });
}

let decryptCounter = 0; // 복호화 시도 카운터

// --- 라우트 설정 ---
app.get('/', (req, res) => res.render('encrypt')); // 암호화 페이지 렌더링
app.get('/decrypt', (req, res) => res.render('decrypt')); // 복호화 페이지 렌더링
app.get('/admin', (req, res) => res.render('admin', { error: null })); // 관리자 로그인 페이지 렌더링

// 관리자 로그인 처리
app.post('/admin-login', (req, res) => {
  const { password } = req.body;
  db.get(`SELECT value FROM config WHERE key = 'admin_pw'`, (err, row) => {
    if (err) {
      console.error('관리자 비밀번호 조회 오류:', err.message);
      return res.render('admin', { error: '로그인 중 오류가 발생했습니다.' });
    }
    const hashed = crypto.createHash('sha256').update(password).digest('hex');
    if (row && row.value === hashed) {
      res.render('admin-panel'); // 비밀번호 일치 시 관리자 패널 렌더링
    } else {
      res.render('admin', { error: '비밀번호가 틀렸습니다.' }); // 비밀번호 불일치 시 에러 메시지
    }
  });
});

// 키 재생성 요청 처리
app.post('/regen-keys', (req, res) => {
  regenKeys('main')
    .then(() => res.json({ status: 'success', message: '키 재생성이 완료되었습니다.' }))
    .catch((error) => res.status(500).json({ status: 'error', message: `키 재생성 실패: ${error.message}` }));
});

// 텍스트 이중 암호화 요청 처리
app.post('/encrypt', (req, res) => {
  getKeys('main', keys => {
    const { text, keyIndex } = req.body; // 암호화할 텍스트와 사용할 pub 키 인덱스

    // 첫 번째 암호화 키 (사용자가 선택한 공개키)
    const pubEncryptionKey = keys.pub[keyIndex];
    // 두 번째 암호화 키 (서버의 메인 키)
    const mainEncryptionKey = keys.main;

    if (!pubEncryptionKey || !mainEncryptionKey) {
        return res.status(400).json({ error: '암호화에 필요한 키가 유효하지 않습니다. 서버 상태를 확인해주세요.' });
    }

    try {
      // 1단계 암호화: 원본 텍스트 -> pub 키
      const firstEncrypted = aesEncrypt(text, pubEncryptionKey);
      // 2단계 암호화: 1단계 결과 -> main 키
      const finalEncrypted = aesEncrypt(firstEncrypted, mainEncryptionKey);

      logAction('ENCRYPT', `TEXT="${text}", PUB_KEY_INDEX=${keyIndex}, MAIN_KEY_USED`);
      res.json({ encrypted: finalEncrypted }); // 최종 암호화된 텍스트 반환
    } catch (e) {
      console.error('이중 암호화 오류:', e.message);
      res.status(500).json({ error: '텍스트 이중 암호화 중 오류가 발생했습니다.' });
    }
  });
});

// 텍스트 이중 복호화 요청 처리
app.post('/decrypt', (req, res) => {
  getKeys('main', keys => {
    const { text, publicKey } = req.body; // 암호화된 텍스트와 첫 번째 복호화에 필요한 공개키 값

    // 1단계 복호화 키 (서버의 메인 키)
    const mainDecryptionKey = keys.main;
    // 2단계 복호화 키 (사용자가 입력한 공개키)
    const pubDecryptionKey = publicKey;

    if (!mainDecryptionKey) {
        return res.status(500).json({ error: '복호화에 필요한 메인 키를 찾을 수 없습니다. 서버 상태를 확인해주세요.' });
    }

    // 사용자 입력 publicKey 값 유효성 검증
    if (!pubDecryptionKey || !/^[0-9a-fA-F]{64}$/.test(pubDecryptionKey)) {
        return res.status(400).json({ error: '유효하지 않거나 형식이 올바르지 않은 공개키 값입니다. 64자리 16진수 문자열이어야 합니다.' });
    }

    try {
      // 1단계 복호화: 최종 암호문 -> main 키 (중간 암호문 얻기)
      const firstDecrypted = aesDecrypt(text, mainDecryptionKey);
      // 2단계 복호화: 중간 암호문 -> 사용자 입력 pub 키 (원본 텍스트 얻기)
      const originalDecrypted = aesDecrypt(firstDecrypted, pubDecryptionKey);

      logAction('DECRYPT', `ORIGINAL="${originalDecrypted}", PUB_KEY_USED="${pubDecryptionKey.substring(0, 8)}...", MAIN_KEY_USED`);
      decryptCounter++; // 복호화 성공 카운터 증가
      if (decryptCounter >= 7) { // 7회 복호화 성공 시
        decryptCounter = 0; // 카운터 초기화
        regenKeys('special'); // 'special' 그룹 키 재생성 (예시 로직)
        console.log("7회 복호화 성공, 'special' 키 재생성 트리거.");
      }
      res.json({ decrypted: originalDecrypted }); // 최종 복호화된 텍스트 반환
    } catch (e) {
      console.error('이중 복호화 오류:', e.message);
      res.status(400).json({ error: '복호화 실패: 암호문, 메인 키 또는 공개키가 올바르지 않습니다. (키값 형식, 길이, 암호화 시 사용한 키 일치 여부 확인)' });
    }
  });
});
