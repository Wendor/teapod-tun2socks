package com.teapodstream.tun2socks

import android.content.Context
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.RequiresApi
import tun2socks.TeapodTun2socks

/**
 * Публичный менеджер teapod-tun2socks.
 *
 * Этот класс является основным API-интерфейсом библиотеки AAR.
 * Он принимает [ParcelFileDescriptor] от Android VpnService,
 * настраивает SOCKS5-прокси и управляет валидацией UID.
 *
 * ## Пример использования:
 *
 * ```kotlin
 * val manager = TeapodVpnManager(context)
 *
 * manager.start(
 *     tunFd = vpnServiceInterface,
 *     socksHost = "proxy.example.com",
 *     socksPort = 1080,
 *     socksUsername = "user",
 *     socksPassword = "pass",
 *     allowedUids = setOf(10086, 10087),
 *     whitelistMode = WhitelistMode.ALLOW_ONLY
 * )
 *
 * // ... позже ...
 * manager.stop()
 * ```
 *
 * ## Требования:
 *  - Минимальная версия Android API: 29 (Q)
 *  - Разрешение ACCESS_NETWORK_STATE (для getConnectionOwnerUid)
 */
@RequiresApi(Build.VERSION_CODES.Q)
class TeapodVpnManager(private val context: Context) {

    @Volatile
    private var teapodTun2socks: TeapodTun2socks? = null

    @Volatile
    private var isStarted = false

    /**
     * Запускает teapod-tun2socks.
     *
     * @param tunFd          TUN-интерфейс (ParcelFileDescriptor от VpnService)
     * @param mtu            MTU TUN-интерфейса; должен совпадать со значением VpnService.Builder.setMtu()
     * @param socksHost      Адрес SOCKS5 прокси
     * @param socksPort      Порт SOCKS5 прокси
     * @param socksUsername  Имя пользователя SOCKS5 (пустая строка = без авторизации)
     * @param socksPassword  Пароль SOCKS5 (пустая строка = без авторизации)
     * @param allowedUids    Набор UID, которые разрешены (или заблокированы, в зависимости от режима)
     * @param whitelistMode  Режим whitelist: [WhitelistMode.ALLOW_ONLY], [WhitelistMode.DENY_ONLY], [WhitelistMode.ALLOW_ALL]
     * @param cacheCapacity  Размер LRU-кэша валидаций (по умолчанию 10000)
     * @param cacheTtlSeconds TTL записей кэша в секундах (по умолчанию 300)
     * @param customValidator Дополнительный пользовательский валидатор (может быть null)
     *
     * @throws IllegalStateException если менеджер уже запущен
     * @throws IllegalArgumentException если tunFd невалиден
     */
    @Synchronized
    fun start(
        tunFd: ParcelFileDescriptor,
        mtu: Int = DEFAULT_MTU,
        socksHost: String,
        socksPort: Int,
        socksUsername: String = "",
        socksPassword: String = "",
        allowedUids: Set<Int> = emptySet(),
        whitelistMode: WhitelistMode = WhitelistMode.ALLOW_ONLY,
        cacheCapacity: Int = DEFAULT_CACHE_CAPACITY,
        cacheTtlSeconds: Int = DEFAULT_CACHE_TTL,
        customValidator: UidValidator? = null
    ) {
        if (isStarted) {
            throw IllegalStateException("TeapodVpnManager уже запущен. Вызовите stop() перед start().")
        }

        val fd = tunFd.fd
        if (fd < 0) {
            throw IllegalArgumentException("ParcelFileDescriptor содержит невалидный fd: $fd")
        }

        Log.i(TAG, "Starting teapod-tun2socks: fd=$fd mtu=$mtu socks=$socksHost:$socksPort mode=$whitelistMode uids=${allowedUids.size}")

        // Создаём резолвер UID
        val uidResolver = UidResolver(context)

        // Создаём callback-адаптер, который будет вызываться из Go
        val callback = TeapodTun2socksCallback(
            uidResolver = uidResolver,
            allowedUids = allowedUids,
            whitelistMode = whitelistMode,
            validator = customValidator
        )

        // Создаём Go teapod-tun2socks
        teapodTun2socks = TeapodTun2socks().apply {
            setLogEnabled(ENABLE_DEBUG_LOGS)
            val error = start(
                fd.toLong(),
                mtu.toLong(),
                socksHost,
                socksPort.toLong(),
                socksUsername,
                socksPassword,
                cacheCapacity.toLong(),
                cacheTtlSeconds.toLong(),
                callback
            )
            if (error.isNotEmpty()) {
                Log.e(TAG, "Ошибка при запуске teapod-tun2socks: $error")
                throw IllegalStateException("teapod-tun2socks start failed: $error")
            }
        }

        isStarted = true
        Log.i(TAG, "teapod-tun2socks запущен успешно")
    }

    /**
     * Останавливает teapod-tun2socks и освобождает ресурсы.
     *
     * Этот метод блокируется до завершения всех горутин Go-движка.
     */
    @Synchronized
    fun stop() {
        if (!isStarted) {
            Log.w(TAG, "stop() вызван, но teapod-tun2socks не запущен")
            return
        }

        Log.i(TAG, "Stopping teapod-tun2socks...")

        try {
            teapodTun2socks?.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка при остановке teapod-tun2socks: ${e.message}", e)
        } finally {
            teapodTun2socks = null
            isStarted = false
            Log.i(TAG, "teapod-tun2socks остановлен")
        }
    }

    /**
     * Возвращает true, если менеджер в данный момент запущен.
     */
    fun isRunning(): Boolean {
        return teapodTun2socks?.isRunning() == true
    }

    /**
     * Возвращает текущий размер кэша UID-валидаций (для отладки).
     */
    fun getCacheSize(): Int {
        return teapodTun2socks?.cacheSize()?.toInt() ?: 0
    }

    /**
     * Переключает внутреннее логирование Go-слоя.
     */
    fun setDebugLogging(enabled: Boolean) {
        teapodTun2socks?.setLogEnabled(enabled)
    }

    /**
     * Возвращает общее количество байт, отправленных через TUN (Upload в интернет).
     */
    fun getUploadBytes(): Long {
        return teapodTun2socks?.uploadBytes ?: 0L
    }

    /**
     * Возвращает общее количество байт, полученных через TUN (Download из интернета).
     */
    fun getDownloadBytes(): Long {
        return teapodTun2socks?.downloadBytes ?: 0L
    }

    companion object {
        private const val TAG = "TeapodVpnManager"

        /** Размер LRU-кэша по умолчанию (записей). */
        const val DEFAULT_CACHE_CAPACITY = 10000

        /** TTL записей кэша по умолчанию (секунды = 5 минут). */
        const val DEFAULT_CACHE_TTL = 300

        /** MTU TUN-интерфейса по умолчанию. */
        const val DEFAULT_MTU = 1500

        /** Включить DEBUG-логи Go-слоя (для разработки). */
        private const val ENABLE_DEBUG_LOGS = false
    }
}
