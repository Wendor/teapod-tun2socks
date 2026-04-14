package com.teapodstream.tun2socks

import android.util.Log
import tun2socks.UIDValidatorFunc

/**
 * Адаптер между Go-слоем (gomobile) и Kotlin-валидатором.
 * Реализует строгую проверку UID для предотвращения обхода VPN.
 */
class TeapodTun2socksCallback(
    private val uidResolver: UidResolver,
    private val allowedUids: Set<Int>,
    private val validator: UidValidator? = null
) : UIDValidatorFunc {

    constructor(
        uidResolver: UidResolver,
        allowedUids: Set<Int>,
        whitelistMode: WhitelistMode,
        validator: UidValidator? = null
    ) : this(uidResolver, allowedUids, validator) {
        this.whitelistMode = whitelistMode
    }

    private var whitelistMode: WhitelistMode = WhitelistMode.ALLOW_ONLY

    override fun validate(
        srcIP: String,
        srcPort: Long,
        dstIP: String,
        dstPort: Long,
        protocol: Long
    ): Boolean {
        val startTime = System.nanoTime()

        // 1. Определяем UID владельца соединения.
        // Go теперь передает: srcIP = телефон (локальный), dstIP = интернет (удаленный).
        val uid = uidResolver.resolveUid(srcIP, srcPort.toInt(), dstIP, dstPort.toInt(), protocol.toInt())
        
        // 2. Проверяем UID. 
        // Если UID < 0 (-1), значит владелец не найден. Дропаем пакет для безопасности.
        val isAllowed = if (uid < 0) {
            false
        } else {
            checkUidWhitelist(uid)
        }

        // 3. Дополнительный пользовательский валидатор (если задан)
        val finalAllowed = isAllowed && (validator?.validate(srcIP, srcPort.toInt(), dstIP, dstPort.toInt(), protocol.toInt()) != false)

        val elapsedMs = (System.nanoTime() - startTime) / 1_000_000.0
        if (!finalAllowed) {
            Log.w(TAG, "DENY: uid=$uid ($srcIP:$srcPort -> $dstIP:$dstPort proto=$protocol) ${elapsedMs.toInt()}ms")
        } else {
            Log.d(TAG, "ALLOW: uid=$uid ($srcIP:$srcPort -> $dstIP:$dstPort proto=$protocol) ${elapsedMs.toInt()}ms")
        }

        return finalAllowed
    }

    private fun checkUidWhitelist(uid: Int): Boolean = when (whitelistMode) {
        WhitelistMode.ALLOW_ONLY -> uid in allowedUids
        WhitelistMode.DENY_ONLY  -> uid !in allowedUids
        WhitelistMode.ALLOW_ALL  -> true
    }

    companion object {
        private const val TAG = "TeapodTun2socksCallback"
    }
}

enum class WhitelistMode {
    ALLOW_ONLY,
    DENY_ONLY,
    ALLOW_ALL
}
