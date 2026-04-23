# Анализ прошивок `.PZU`

Дата анализа: 2026-04-23 (UTC).

## Что находится в репозитории

В репозитории присутствуют несколько образов ПЗУ в текстовом HEX-виде:

- `A03_26.PZU`
- `A04_28.PZU`
- `ppkp2012 a01.PZU`
- `ppkp2019 a02.PZU`

По структуре строк (`:LLAAAATT...CC`) это формат Intel HEX.

## Быстрая валидация Intel HEX

Выполнена проверка структуры записей, длины, контрольной суммы и диапазона адресов.

Результат:

- `A03_26.PZU`: **valid=True**, `data_records=512`, `data_bytes=32768`, `addr_range=0x4000-0xBFFF`
- `A04_28.PZU`: **valid=True**, `data_records=512`, `data_bytes=32768`, `addr_range=0x4000-0xBFFF`
- `ppkp2012 a01.PZU`: **valid=False**, ошибка checksum на строке 512
- `ppkp2019 a02.PZU`: **valid=False**, ошибка checksum на строке 512

## Реверс `ppkp2019 a02.PZU` (статический)

### Идентификаторы сборки/платформы

В данных образа обнаружены строковые маркеры:

- `ppkp2019 A.02`
- `Ver.2013s/ RTOS`
- `v45.0`, `v53`, `v54`, `v55`, `v51.c`, `v51.d`

### UI/операторские команды

Обнаружены маркеры интерфейса:

- `<FUNC>`
- `<ENTER>`
- `<ACTIV>`
- `<SILENCE>`
- `<RESET>`

### Часто вызываемые подпрограммы (эвристика по `LCALL`)

Топ-целей вызовов:

- `0x92EF` (~260)
- `0x9489` (~78)
- `0x94D6` (~63)
- `0x9490` (~57)
- `0x8211` (~51)

Это похоже на сервисный слой прошивки (вспомогательные операции, доступ к таблицам/данным, поддержка бизнес-логики).

### Предварительное разбиение областей

- `0x4000..0x43FF`: старт/переходы/инициализация
- `0x4400..0x5FFF`: основная прикладная логика
- `~0x9F40+`: области UI-строк и таблиц
- `0x92xx..0x94xx`: интенсивно вызываемый сервисный слой

## Ограничения

- `.PZU` не является исполняемым файлом для ПК.
- Для полноценного динамического запуска нужен эмулятор/железо целевого микроконтроллера и модель периферии.

## Воспроизводимость (команды)

Ниже команды, которыми получены основные результаты:

```bash
python3 - <<'PY'
from pathlib import Path
files=sorted(Path('.').glob('*.PZU'))
for f in files:
    ok=True; records=0; data_bytes=0; min_addr=10**9; max_addr=0
    for i,line in enumerate(f.read_text(errors='ignore').splitlines(),1):
        line=line.strip()
        if not line: continue
        if not line.startswith(':'): ok=False; break
        hexs=line[1:]
        if len(hexs)%2: ok=False; break
        b=bytes.fromhex(hexs)
        ll=b[0]; addr=(b[1]<<8)|b[2]; rtype=b[3]; data=b[4:-1]
        if ll!=len(data): ok=False; break
        if ((sum(b)&0xFF)!=0): ok=False; break
        if rtype==0:
            records+=1; data_bytes+=ll
            min_addr=min(min_addr,addr); max_addr=max(max_addr,addr+ll-1)
    print(f'{f.name}: valid={ok}, data_records={records}, data_bytes={data_bytes}, addr_range=0x{min_addr:04X}-0x{max_addr:04X}')
PY
```

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter
f=Path('ppkp2019 a02.PZU')
mem=bytearray([0xFF]*0x10000)
for line in f.read_text().splitlines():
    b=bytes.fromhex(line[1:]); ll=b[0]; addr=(b[1]<<8)|b[2]; typ=b[3]
    if typ==0: mem[addr:addr+ll]=b[4:4+ll]
calls=Counter()
for i in range(0x4000,0xBFFF-2):
    if mem[i]==0x12:
        calls[(mem[i+1]<<8)|mem[i+2]] += 1
print(calls.most_common(15))
PY
```

```bash
rg -n "3C46554E433E|3C454E5445523E|3C41435449563E|3C53494C454E43453E|3C52455345543E|70706B703230313920412E3032|5665722E32303133732F2052544F5320|7634352E30" "ppkp2019 a02.PZU"
```

