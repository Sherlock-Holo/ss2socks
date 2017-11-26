package config

import org.yaml.snakeyaml.Yaml
import java.io.File
import java.io.FileInputStream

data class ServerConfig(val ssAddr: String, val ssPort: Int, val backEndAddr: String, val backEndPort: Int)

class config {
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

    fun printAll() {
        println(yamlConfig)
    }

    fun getConfig(): ServerConfig {
        return ServerConfig(yamlConfig["ssAddr"] as String, yamlConfig["ssPort"] as Int, yamlConfig["backEndAddr"] as String, yamlConfig["backEndPort"] as Int)
    }
}

fun main(args: Array<String>) {
    val yaml = config(FileInputStream(File("/home/sherlock/git/ss2socks/src/main/kotlin/config/config.yaml")))
    yaml.printAll()
    println(yaml.getConfig())
}