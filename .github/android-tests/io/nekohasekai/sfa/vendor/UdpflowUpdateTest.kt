package io.nekohasekai.sfa.vendor

import io.nekohasekai.sfa.update.UpdateTrack
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UdpflowUpdateTest {
    private fun release(version: String = "1.14.0-udpflow") = GitHubUpdateChecker.GitHubRelease(
        tagName = "v$version",
        htmlUrl = "https://github.com/shinokiri/sing-box/releases/tag/v$version",
        assets = listOf(
            GitHubUpdateChecker.GitHubAsset("SFA-$version-arm64-v8a.apk", "https://example.com/arm64.apk", 123),
            GitHubUpdateChecker.GitHubAsset("SFA-$version-x86_64.apk", "https://example.com/x86.apk", 456),
        ),
    )

    @Test
    fun checksTheFork() {
        assertEquals("https://api.github.com/repos/shinokiri/sing-box/releases?per_page=100", GitHubUpdateChecker.RELEASES_URL)
    }

    @Test
    fun higherVersionCodeWithTheSameDisplayNameIsAnUpdate() {
        val update = selectUdpflowUpdate(listOf(release()), UpdateTrack.STABLE, 1000060) {
            GitHubUpdateChecker.VersionMetadata(1000061, "1.14.0-udpflow")
        }
        assertEquals(1000061, update?.versionCode)
        assertEquals("1.14.0-udpflow", update?.versionName)
        assertEquals("https://example.com/arm64.apk", update?.downloadUrl)
        assertEquals(123L, update?.fileSize)
    }

    @Test
    fun doesNotOfferAnUninstallableEqualOrLowerCode() {
        for (code in listOf(0, 730, 1000060)) {
            assertNull(selectUdpflowUpdate(listOf(release("1.15.0-udpflow")), UpdateTrack.STABLE, 1000060) {
                GitHubUpdateChecker.VersionMetadata(code, "1.15.0-udpflow")
            })
        }
    }

    @Test
    fun stableTrackSkipsDraftsAndPrereleases() {
        for (release in listOf(release().copy(draft = true), release().copy(prerelease = true))) {
            assertNull(selectUdpflowUpdate(listOf(release), UpdateTrack.STABLE, 1000060) {
                error("Excluded releases must not request their metadata")
            })
        }
    }

    @Test
    fun betaTrackCanSelectAPrerelease() {
        val update = selectUdpflowUpdate(listOf(release().copy(prerelease = true)), UpdateTrack.BETA, 1000060) {
            GitHubUpdateChecker.VersionMetadata(1000061, "1.14.0-udpflow")
        }
        assertEquals(true, update?.isPrerelease)
    }

    @Test
    fun incompleteReleasesDoNotHideTheLastInstallableUpdate() {
        val releases = listOf(release("1.14.2-udpflow"), release("1.14.1-udpflow").copy(assets = emptyList()), release())
        val update = selectUdpflowUpdate(releases, UpdateTrack.STABLE, 1000060) {
            when (it.tagName) {
                "v1.14.2-udpflow" -> null
                "v1.14.1-udpflow" -> GitHubUpdateChecker.VersionMetadata(1000063, "1.14.1-udpflow")
                else -> GitHubUpdateChecker.VersionMetadata(1000061, "1.14.0-udpflow")
            }
        }
        assertEquals("1.14.0-udpflow", update?.versionName)
    }

    @Test
    fun choosesTheHighestCodeRegardlessOfApiOrdering() {
        val releases = listOf(release(), release("1.14.1-udpflow"))
        for (ordered in listOf(releases, releases.reversed())) {
            val update = selectUdpflowUpdate(ordered, UpdateTrack.STABLE, 1000060) {
                if (it.tagName == "v1.14.0-udpflow") GitHubUpdateChecker.VersionMetadata(1000061, "1.14.0-udpflow")
                else GitHubUpdateChecker.VersionMetadata(1000062, "1.14.1-udpflow")
            }
            assertEquals("1.14.1-udpflow", update?.versionName)
        }
    }

    @Test
    fun rejectsMetadataFromAnotherReleaseAndWrongArchitecture() {
        assertNull(selectUdpflowUpdate(listOf(release()), UpdateTrack.STABLE, 1000060) {
            GitHubUpdateChecker.VersionMetadata(1000061, "1.14.1-udpflow")
        })
        assertNull(selectUdpflowUpdate(listOf(release().copy(assets = release().assets.drop(1))), UpdateTrack.STABLE, 1000060) {
            GitHubUpdateChecker.VersionMetadata(1000061, "1.14.0-udpflow")
        })
    }
}
