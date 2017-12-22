package config

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