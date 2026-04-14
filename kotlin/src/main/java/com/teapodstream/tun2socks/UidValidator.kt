package com.teapodstream.tun2socks

/**
 * Интерфейс валидации UID-соединений.
 *
 * Реализация этого интерфейса передаётся в слой Go через gomobile-биндинг
 * и вызывается синхронно для каждого нового TCP/UDP соединения до того,
 * как трафик будет перенаправлен в SOCKS5 прокси.
 *
 * Если [validate] возвращает false, соединение блокируется:
 *  - Для TCP: отправляется RST-пакет обратно в TUN
 *  - Для UDP: пакет молча дропается
 */
interface UidValidator {

    /**
     * Вызывается из Go-слоя для проверки нового соединения.
     *
     * @param srcAddr  IP-адрес источника (локальный, из TUN)
     * @param srcPort  Порт источника
     * @param dstAddr  IP-адрес назначения (целевой сервер)
     * @param dstPort  Порт назначения
     * @param protocol Номер протора: [android.system.OsConstants.IPPROTO_TCP] (6)
     *                 или [android.system.OsConstants.IPPROTO_UDP] (17)
     * @return true если соединение разрешено, false если заблокировано
     */
    fun validate(
        srcAddr: String,
        srcPort: Int,
        dstAddr: String,
        dstPort: Int,
        protocol: Int
    ): Boolean
}
