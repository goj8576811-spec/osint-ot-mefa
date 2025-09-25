/* ===== Общие утилиты (обе страницы) ===== */
window.addEventListener('load', () => document.body.classList.add('loaded'));

function showModal(id){
  const m = document.getElementById(id);
  if (!m) return;
  m.style.display = '';
  m.classList.add('show');
}
function closeModal(id){
  const m = document.getElementById(id);
  if (!m) return;
  m.classList.remove('show');
}
window.addEventListener('click', (e) => {
  document.querySelectorAll('.modal').forEach(m => {
    if (e.target === m) m.classList.remove('show');
  });
});

/* ===== ДАННЫЕ (ветви → категории → инструменты) ===== */
const branches = {
  osint: {
    title: "🌐 OSINT",
    categories: {
      nickmail: {
        title: "Ник / Email",
        tools: [
          {name:"Sherlock", desc:"Поиск профилей по нику (CLI).", link:"https://github.com/sherlock-project/sherlock"},
          {name:"Maigret", desc:"Альтернатива Sherlock с большим охватом.", link:"https://github.com/soxoj/maigret"},
          {name:"WhatsMyName", desc:"Онлайн-поиск ников.", link:"https://whatsmyname.app"},
          {name:"Holehe", desc:"Где зарегистрирован email.", link:"https://github.com/megadose/holehe"},
          {name:"Epieos", desc:"Следы email, календари.", link:"https://epieos.com"},
          {name:"Hunter.io", desc:"Email ↔ домен, поиск и верификация.", link:"https://hunter.io"},
          {name:"EmailRep", desc:"Репутация почты.", link:"https://emailrep.io"},
          {name:"Namechk", desc:"Проверка никнейма.", link:"https://namechk.com"},
          {name:"KnowEm", desc:"Занятость имени в соцсетях.", link:"https://knowem.com"}
        ]
      },
      phones: {
        title: "Телефоны",
        tools: [
          {name:"PhoneInfoga", desc:"OSINT по номеру.", link:"https://github.com/sundowndev/PhoneInfoga"},
          {name:"Truecaller", desc:"Идентификация номеров.", link:"https://www.truecaller.com"},
          {name:"GetContact", desc:"Как записан номер у других.", link:"https://getcontact.com"},
          {name:"NumVerify", desc:"API валидации номера.", link:"https://numverify.com"},
          {name:"Twilio Lookup", desc:"Carrier lookup.", link:"https://www.twilio.com/lookup"},
          {name:"Sync.me", desc:"Caller ID.", link:"https://sync.me"}
        ]
      },
      leaks: {
        title: "Утечки и базы",
        tools: [
          {name:"DeHashed", desc:"Поиск по крупным утечкам.", link:"https://dehashed.com"},
          {name:"Have I Been Pwned", desc:"Проверка email/паролей.", link:"https://haveibeenpwned.com"},
          {name:"IntelX", desc:"Индексы/утечки/файлы.", link:"https://intelx.io"},
          {name:"Snusbase", desc:"Агрегатор утечек.", link:"https://snusbase.com"},
          {name:"LeakCheck", desc:"Поиск по утечкам.", link:"https://leakcheck.io"},
          {name:"LeakIX", desc:"Экспозы и индексы.", link:"https://leakix.net"},
          {name:"BreachDirectory", desc:"Агрегатор утечек.", link:"https://breachdirectory.org"},
          {name:"Pastebin", desc:"Пасты (часто сливы).", link:"https://pastebin.com"},
          {name:"Pwned Passwords", desc:"Скомпрометированные пароли.", link:"https://haveibeenpwned.com/Passwords"}
        ]
      },
      dorks: {
        title: "Dorks / Индекс",
        tools: [
          {name:"Google Dork List", desc:"Справочник dork-запросов.", link:"https://github.com/kozmer/google-dork-list"},
          {name:"PublicWWW", desc:"Поиск по коду сайтов.", link:"https://publicwww.com"},
          {name:"Wayback Machine", desc:"Архив старых страниц.", link:"https://archive.org/web/"}
        ]
      }
    }
  },

  humint: {
    title: "🧑 HUMINT",
    categories: {
      forums: {
        title: "Форумы / обсуждения",
        tools: [
          {name:"Reddit", desc:"Инсайты и обсуждения.", link:"https://www.reddit.com"},
          {name:"Stack Exchange", desc:"QA-сети по тематикам.", link:"https://stackexchange.com"},
          {name:"Telegram Search", desc:"Поиск по публичным каналам.", link:"https://t.me/s"}
        ]
      },
      contacts: {
        title: "Публичные профили",
        tools: [
          {name:"LinkedIn", desc:"Профили и связи.", link:"https://www.linkedin.com"},
          {name:"AngelList", desc:"Профили в стартап-среде.", link:"https://angel.co"}
        ]
      }
    }
  },

  socmint: {
    title: "💬 SOCMINT",
    categories: {
      telegram: {
        title: "Telegram",
        tools: [
          {name:"TGStat", desc:"Аналитика каналов.", link:"https://tgstat.ru"},
          {name:"Telemetr", desc:"Мониторинг и статистика.", link:"https://telemetr.me"},
          {name:"Combot", desc:"Статистика и антиспам.", link:"https://combot.org"}
        ]
      },
      vk: {
        title: "ВКонтакте",
        tools: [
          {name:"VK (официально)", desc:"Поиск людей/групп/постов.", link:"https://vk.com"}
        ]
      },
      twitter: {
        title: "Twitter / X",
        tools: [
          {name:"Twitonomy", desc:"Аналитика аккаунтов.", link:"https://www.twitonomy.com"},
          {name:"Social Bearing", desc:"Поиск/фильтр твитов.", link:"https://socialbearing.com"}
        ]
      },
      instagram: {
        title: "Instagram",
        tools: [
          {name:"Instaloader", desc:"Скачивание/метаданные (CLI).", link:"https://github.com/instaloader/instaloader"}
        ]
      }
    }
  },

  geoint: {
    title: "🗺 GEOINT",
    categories: {
      maps: {
        title: "Карты / спутники",
        tools: [
          {name:"Google Maps", desc:"Карты и Street View.", link:"https://maps.google.com"},
          {name:"Yandex Maps", desc:"Карты и панорамы (СНГ).", link:"https://yandex.ru/maps"},
          {name:"Zoom Earth", desc:"Снимки Земли онлайн.", link:"https://zoom.earth"},
          {name:"Sentinel Hub", desc:"Спутниковые данные.", link:"https://www.sentinel-hub.com"},
          {name:"OpenStreetMap", desc:"Открытая карта мира.", link:"https://www.openstreetmap.org"}
        ]
      },
      reverseimg: {
        title: "По изображению",
        tools: [
          {name:"TinEye", desc:"Обратный поиск изображений.", link:"https://tineye.com"},
          {name:"Google Images", desc:"Поиск по картинке.", link:"https://images.google.com"}
        ]
      }
    }
  },

  sigint: {
    title: "📡 SIGINT",
    categories: {
      networks: {
        title: "Сети / устройства",
        tools: [
          {name:"Shodan", desc:"Поиск устройств.", link:"https://www.shodan.io"},
          {name:"Censys", desc:"Хосты и сертификаты.", link:"https://censys.io"},
          {name:"ZoomEye", desc:"Хосты/порты.", link:"https://www.zoomeye.org"},
          {name:"BinaryEdge", desc:"Internet scanning.", link:"https://www.binaryedge.io"},
          {name:"Netlas", desc:"Сервисы/подсети/доменные связи.", link:"https://netlas.io"}
        ]
      }
    }
  },

  cybint: {
    title: "💻 CYBINT",
    categories: {
      domains: {
        title: "Домены / хосты / DNS",
        tools: [
          {name:"DomainTools WHOIS", desc:"WHOIS/история/риск.", link:"https://whois.domaintools.com"},
          {name:"VirusTotal", desc:"URL/домен/файл анализ.", link:"https://www.virustotal.com"},
          {name:"urlscan.io", desc:"Скан страницы и артефакты.", link:"https://urlscan.io"},
          {name:"SecurityTrails", desc:"DNS/PDNS, субдомены.", link:"https://securitytrails.com"},
          {name:"CIRCL Passive DNS", desc:"Пассивный DNS.", link:"https://www.circl.lu/services/passive-dns/"}
        ]
      },
      malware: {
        title: "Malware / IoC",
        tools: [
          {name:"Hybrid Analysis", desc:"Статический/динамический анализ.", link:"https://www.hybrid-analysis.com"},
          {name:"MalwareBazaar", desc:"IoC/сэмплы от abuse.ch", link:"https://bazaar.abuse.ch"},
          {name:"ANY.RUN", desc:"Интерактивная песочница.", link:"https://any.run"}
        ]
      }
    }
  },

  finint: {
    title: "💰 FININT",
    categories: {
      crypto: {
        title: "Блокчейн / кошельки",
        tools: [
          {name:"Etherscan", desc:"Ethereum-эксплорер.", link:"https://etherscan.io"},
          {name:"Blockchain.com Explorer", desc:"BTC-эксплорер.", link:"https://www.blockchain.com/explorer"},
          {name:"Tronscan", desc:"TRON-эксплорер.", link:"https://tronscan.org"},
          {name:"Blockchair", desc:"Мульти-блокчейн эксплорер.", link:"https://blockchair.com"}
        ]
      }
    }
  },

  masint: {
    title: "⚙ MASINT",
    categories: {
      media: {
        title: "Фото / Видео / Метаданные",
        tools: [
          {name:"ExifTool", desc:"EXIF/метаданные изображений.", link:"https://exiftool.org"},
          {name:"InVID", desc:"Верификация видео.", link:"https://www.invid-project.eu"},
          {name:"FotoForensics", desc:"ELA/анализ изображений.", link:"http://fotoforensics.com"}
        ]
      }
    }
  }
};

/* ===== Рендер ветвей (search.html) ===== */
(function renderBranches(){
  const wrap = document.getElementById('branchList');
  if (!wrap) return; // если мы на index.html
  let html = '';
  Object.keys(branches).forEach(key => {
    html += `<button class="branch-btn" onclick="openBranch('${key}')">${branches[key].title}</button>`;
  });
  wrap.innerHTML = html;
})();

/* ===== Навигация: ветвь → категории → инструменты ===== */
let currentBranchKey = null;

function openBranch(key){
  currentBranchKey = key;
  const branch = branches[key];
  document.getElementById('categoryTitle').textContent = branch.title;

  let html = '';
  Object.keys(branch.categories).forEach(catKey => {
    const cat = branch.categories[catKey];
    html += `<button class="category-item" onclick="openCategory('${key}','${catKey}')">${cat.title}</button>`;
  });
  document.getElementById('categoryList').innerHTML = `<div class="fade-list">${html}</div>`;
  showModal('categoryModal');
}

function openCategory(branchKey, catKey){
  const cat = branches[branchKey].categories[catKey];
  document.getElementById('toolsTitle').textContent = cat.title;

  let html = '';
  cat.tools.forEach(t => {
    html += `<div class="tool-item">
      <h3>${escapeHtml(t.name)}</h3>
      <p>${escapeHtml(t.desc)}</p>
      <a href="${t.link}" target="_blank" rel="noopener">Перейти</a>
    </div>`;
  });
  document.getElementById('toolsList').innerHTML = `<div class="fade-list">${html}</div>`;
  closeModal('categoryModal');
  showModal('toolsModal');
}

function backToCategories(){
  if (!currentBranchKey) { closeModal('toolsModal'); return; }
  openBranch(currentBranchKey);
  closeModal('toolsModal');
}

/* ===== Вспомогательное ===== */
function escapeHtml(str){
  return String(str||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
