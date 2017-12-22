package config

import com.moandjiezana.toml.Toml
import java.io.File

class Config(file: File) {
    private val tomlConfig = Toml().read(file)
    private val config: TopConfig
    init {
        config = tomlConfig.to(TopConfig::class.java)
    }

    class TopConfig {
        lateinit var server: Server
        lateinit var security: Security
        lateinit var securityChannel: SecurityChannel
    }

    class Server {
        lateinit var ssAddr: String
        var ssPort = 0
        lateinit var backEndAddr: String
        var backEndPort = 0
    }

    class Security {
        lateinit var cipherMode: String
        lateinit var password: String
    }

    class SecurityChannel {
        var GeoIP = false
        lateinit var GeoIPDatabaseFilePath: String
    }

    fun getConfig(): TopConfig {
        return config
    }
}

fun main(args: Array<String>) {
    val tomlConfig = Config(File("/home/sherlock/git/ss2socks/src/main/kotlin/config/config.toml")).getConfig()
    println(tomlConfig.security.cipherMode)
}