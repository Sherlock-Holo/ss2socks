package config

import org.yaml.snakeyaml.Yaml
import java.io.File
import java.io.FileInputStream

data class ServerConfig(val ssAddr: String, val ssPort: Int, val backEndAddr: String, val backEndPort: Int, val password: String, val buffer: Int)

class Config {
    private val yamlConfig: Map<String, Any>

    constructor(path: String) {
        yamlConfig = Yaml().load(FileInputStream(path))
    }

    constructor(file: File) {
        yamlConfig = Yaml().load(FileInputStream(file))
    }

    constructor(fileInputStream: FileInputStream) {
        yamlConfig = Yaml().load(fileInputStream)
    }

//    fun printAll() {
//        println(yamlConfig)
//    }

    fun getConfig(): ServerConfig {
        return ServerConfig(yamlConfig["ssAddr"] as String, yamlConfig["ssPort"] as Int, yamlConfig["backEndAddr"] as String, yamlConfig["backEndPort"] as Int, yamlConfig["password"] as String, yamlConfig["buffer"] as Int)
    }
}