package com.teapodstream.tun2socks

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.system.OsConstants
import androidx.annotation.RequiresApi
import java.net.InetSocketAddress

/**
 * Обёртка над [ConnectivityManager.getConnectionOwnerUid] для определения
 * Android UID процесса, которому принадлежит сетевое соединение.
 *
 * Требует Android API 29+.
 */
@RequiresApi(Build.VERSION_CODES.Q)
class UidResolver(private val context: Context) {

    private val connectivityManager: ConnectivityManager by lazy {
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }

    /**
     * Определяет UID владельца соединения.
     *
     * @param srcAddr  Локальный IP-адрес
     * @param srcPort  Локальный порт
     * @param dstAddr  Удалённый IP-адрес
     * @param dstPort  Удалённый порт
     * @param protocol Номер протокола (OsConstants.IPPROTO_TCP или OsConstants.IPPROTO_UDP)
     * @return UID владельца, или -1 если не удалось определить
     */
    fun resolveUid(
        srcAddr: String,
        srcPort: Int,
        dstAddr: String,
        dstPort: Int,
        protocol: Int
    ): Int {
        return try {
            // getConnectionOwnerUid определяет UID приложения, которому принадлежит
            // данная пара local/remote address.
            // Для TCP используем IPPROTO_TCP, для UDP — IPPROTO_UDP.
            val uid = connectivityManager.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(srcAddr, srcPort),
                InetSocketAddress(dstAddr, dstPort)
            )
            uid
        } catch (e: SecurityException) {
            // Требуется разрешение ACCESS_NETWORK_STATE
            android.util.Log.w(
                TAG,
                "SecurityException при getConnectionOwnerUid: ${e.message}"
            )
            -1
        } catch (e: Exception) {
            android.util.Log.e(
                TAG,
                "Ошибка при определении UID для $srcAddr:$srcPort -> $dstAddr:$dstPort: ${e.message}"
            )
            -1
        }
    }

    /**
     * Определяет UID для TCP-соединения.
     */
    fun resolveTcpUid(
        localAddr: String,
        localPort: Int,
        remoteAddr: String,
        remotePort: Int
    ): Int {
        return resolveUid(
            localAddr, localPort, remoteAddr, remotePort,
            OsConstants.IPPROTO_TCP
        )
    }

    /**
     * Определяет UID для UDP-соединения.
     */
    fun resolveUdpUid(
        localAddr: String,
        localPort: Int,
        remoteAddr: String,
        remotePort: Int
    ): Int {
        return resolveUid(
            localAddr, localPort, remoteAddr, remotePort,
            OsConstants.IPPROTO_UDP
        )
    }

    companion object {
        private const val TAG = "UidResolver"
    }
}
