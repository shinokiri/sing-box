package io.nekohasekai.sfa.vendor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

class CachedApkTest {
    @Test
    fun anOlderDownloadedApkCannotBeInstalledAsTheNextRelease() {
        val file = File.createTempFile("udpflow-update", ".apk")
        try {
            file.writeText("previous APK")
            val previous = "https://github.com/shinokiri/sing-box/releases/download/v1.14.0-udpflow/SFA-1.14.0-udpflow-arm64-v8a.apk"
            val next = "https://github.com/shinokiri/sing-box/releases/download/v1.14.0-udpflow.1/SFA-1.14.0-udpflow.1-arm64-v8a.apk"
            assertNull(cachedApkForUrl(file, previous, next))
            assertNull(cachedApkForUrl(file, "", next))
            assertEquals(file, cachedApkForUrl(file, previous, previous))
            file.writeText("")
            assertNull(cachedApkForUrl(file, previous, previous))
        } finally {
            file.delete()
        }
    }
}
