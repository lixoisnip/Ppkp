# Manual decompile milestone #47: 0x728A mode gate and 0x6833 output start

Файл: `90CYE03_19_DKS.PZU` (ветка `90CYE_DKS`).

## 1) Scope

Цель milestone — перевести гипотезу `state -> mode gate -> output start` в полу-ручную декомпиляцию двух узлов:

- `0x728A` как mode-gate (manual/auto split).
- `0x6833` как output/extinguishing start.

Документ фиксирует только статически наблюдаемую семантику (без стендовой валидации).

## 2) Direct entry evidence

- Вход в `0x728A` подтверждён `LCALL` из `0x85D3` (reachable, high).
- Вход в `0x6833` подтверждён `LCALL` из `0x7876` и `LJMP` из `0x7265` (reachable, high).

## 3) 0x728A: manual decompile (mode gate)

### 3.1 Observed control points

Ключевые инструкции/ветки:

- `0x728A..0x7292`: чтение `XDATA 0x30A2` и `0x30E7` в регистры.
- `0x7293`: `JNB 0xE0,+78 -> 0x72E4` (ранний выход `RET`).
- `0x7296`: `JNB 0xE1,+6 -> 0x729F`.
- `0x7299`: `JNB 0xE2,+73 -> 0x72E5` (ветка через `0x72E8`).
- `0x729C`: `LJMP 0x7316` (третья ветка mode split).

### 3.2 Branch semantics (working model)

- **Guard-0** (`bit E0`): если не установлен — быстрый выход (`RET`).
- **Guard-1/2** (`bit E1/E2`): выбирают один из под-потоков обработки:
  - под-поток с подготовкой `0x31BF/0x30E8/0x30E5`, затем `LCALL 0x7366`, packet/export через `0x5A7F`, сервис через `0x7922`/`0x7D7A`, установка бита в `0x30E7`, и переход в `0x6EC2 -> 0x6EE6`;
  - под-поток через `0x7316`, где есть проверка через `0x7D85`, дополнительный gate через `0x7360`, и развилка `0x6ECE -> 0x6EB8` или packet/export путь через `0x5A7F`.

### 3.3 Pseudocode (reconstructed)

```c
void fn_728A(void) {
    uint8_t a30a2 = XDATA[0x30A2];
    uint8_t f30e7 = XDATA[0x30E7];

    if (!BIT(f30e7, E0)) {
        return;  // 0x72E4
    }

    if (BIT(f30e7, E1)) {
        if (BIT(f30e7, E2)) {
            goto path_7316;   // 0x729C
        }
        // path_A: output/event prep + packet bridge
        XDATA[0x31BF] = call_5A7F(0x31BF);
        XDATA[0x30E8] = call_5A7F(0x71A0);
        XDATA[0x30E5] = ACC;
        XDATA[0x30E9] = call_7366();
        call_5A7F(0x7128);
        call_7922();
        call_7D7A(call_5A7F(0x364B));
        XDATA[0x30E7] |= BIT_E1;
        call_6EC2();
        jump_6EE6();
    }

    // path_B (when !E1):
    if (!BIT(f30e7, E2)) {
        if (call_7D85(call_5A7F(0x364B)) != 0) {
            return;
        }
        XDATA[0x30E9] = ACC;
        call_7922(call_5A7F(0x7138));
        call_7D7A(call_5A7F(0x364B));
        XDATA[0x30E7] |= BIT_E2;
        return;
    }

path_7316:
    if (call_7D85(call_5A7F(0x364B)) != 0) {
        return;
    }
    if (call_7360() == 0) {
        call_6ECE();
        XDATA[0x30E7] = ACC;
        XDATA[0x31BF] = call_5A7F(0x31BF);
        jump_6EB8();
    }

    XDATA[0x30E9] = ACC;
    call_7922(call_5A7F(0x7128));
    call_7D7A(call_5A7F(0x364B));
    XDATA[0x30E7] &= ~BIT_E2;
    return;
}
```

## 4) 0x6833: manual decompile (output start)

### 4.1 Observed control points

Ключевые инструкции:

- `0x6833`: `DPTR=#0x7108`, затем `LCALL 0x7922`.
- `0x683A`: `LCALL 0x597F` (результат влияет на ветку через `JB 0xEF,-112 -> 0x67D7`).
- `0x6849`: `LCALL 0x5A7F`, после чего `MOVX @DPTR,#0x04`.
- `0x6850..0x6856`: чтение через `0x71A8` + `LCALL 0x5A7F`.
- `0x685C..0x6862`: `DPTR=#0x364B`, `LCALL 0x5A7F`, `LJMP 0x7DC2`.

### 4.2 Working model

`0x6833` выглядит как короткий стартовый output handler:

1. Инициирует служебный шаг через `0x7922(0x7108)`.
2. Проверяет условие через `0x597F`; при активном флаге уходит в fallback/alt path (`0x67D7`).
3. В основном пути выставляет код `0x04` по адресации, связанной с `0x5A7F`.
4. Берёт дополнительный параметр/состояние через `0x71A8`.
5. Передаёт управление в `0x7DC2` после шага через `0x364B`.

### 4.3 Pseudocode (reconstructed)

```c
void fn_6833(void) {
    call_7922(0x7108);

    uint8_t st = call_597F(/*R7-derived context*/);
    if (BIT(st, EF)) {
        goto alt_67D7;
    }

    dptr = call_5A7F(/*context from R7*/);
    XDATA[dptr] = 0x04;                 // output-start marker candidate

    uint8_t aux = XDATA[call_5A7F(0x71A8)];
    (void)aux;                          // consumed by downstream logic

    jump_7DC2(call_5A7F(0x364B));
}
```

## 5) What changed in confidence

После ручной декомпиляции (без стенда):

- `0x728A` повышается до **probable mode gate** (ветки и side effects хорошо читаются по коду).
- `0x6833` повышается до **probable output-start entry** (короткий и целенаправленный стартовый путь).

Остаётся `hypothesis` на уровне физической трактовки (`relay/valve/exact actuator`).

## 6) Next checks

1. Стенд: manual fire — подтвердить, что путь не уходит в output-start.
2. Стенд: auto fire — подтвердить срабатывание шага, соответствующего `XDATA[dptr]=0x04` и перехода в downstream (`0x7DC2`).
3. Runtime trace: снять изменения `0x30E7`, `0x30E9`, `0x31BF`, `0x364B` вокруг вызовов `0x728A`/`0x6833`.
