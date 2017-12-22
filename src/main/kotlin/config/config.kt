package config

import com.moandjiezana.toml.Toml
import org.yaml.snakeyaml.Yaml
import java.io.File
import java.io.FileInputStream

data class ServerConfig(val ssAddr: String, val ssPort: Int, val backEndAddr: String, val backEndPort: Int,
                        val password: String, val cipherMode: String, val secretChannel: Boolean, val geoIPDataBaseFilePath: String?)

class Config(file: File) {
    private val yamlConfig: Map<String, Any> = Yaml().load(FileInputStream(file))

    fun getConfig(): ServerConfig {
        if (yamlConfig["geoIP"] as Boolean) {
            return ServerConfig(yamlConfig["ssAddr"] as String, yamlConfig["ssPort"] as Int,
                    yamlConfig["backEndAddr"] as String, yamlConfig["backEndPort"] as Int,
                    yamlConfig["password"] as String, yamlConfig["cipherMode"] as String, yamlConfig["geoIP"] as Boolean, yamlConfig["geoIPDatabaseFilePath"] as String)
        }

        return ServerConfig(yamlConfig["ssAddr"] as String, yamlConfig["ssPort"] as Int,
                yamlConfig["backEndAddr"] as String, yamlConfig["backEndPort"] as Int, yamlConfig["password"] as String,
                yamlConfig["cipherMode"] as String, yamlConfig["geoIP"] as Boolean, null)
    }

}

class Server {
    lateinit var ssAddr: String
    var ssPort = 0
    lateinit var backEndAddr: String
    var backEndPort = 0
}

class TopConfig {
    lateinit var server: Server
    lateinit var security: Security
    lateinit var securityChannel: SecurityChannel
}

class Security {
    lateinit var cipherMode: String
    lateinit var password: String
}

class SecurityChannel {
    var GeoIP = false
    lateinit var GeoIPDatabaseFilePath: String
}

fun main(args: Array<String>) {
    val tomlconfig = Toml().read(File("/home/sherlock/git/ss2socks/src/main/kotlin/config/config.toml"))
    val sct = tomlconfig.to(TopConfig::class.java)
    println(sct.server.ssAddr)
}