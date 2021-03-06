package libs.geoIP

import com.maxmind.geoip2.DatabaseReader
import com.maxmind.geoip2.exception.AddressNotFoundException
import com.maxmind.geoip2.model.CityResponse
import java.io.File
import java.net.InetAddress
import kotlin.collections.HashMap


open class GeoIP(filePath: String?) {
    private lateinit var dataBaseFile: File
    private val reader: DatabaseReader?
    private val cache = HashMap<String, String>()

    init {
        if (filePath != null) {
            dataBaseFile = File(filePath)
            reader = DatabaseReader.Builder(dataBaseFile).build()
        } else reader = null
    }

    open fun getIPCountry(rawIP: ByteArray): String? {
        if (reader == null) return null

        val ip = InetAddress.getByAddress(rawIP).hostAddress
        if (cache.containsKey(ip)) return cache[ip]

        val response: CityResponse
        try {
            response = reader.city(InetAddress.getByAddress(rawIP))
        } catch (e: AddressNotFoundException) {
            return null
        }
        val country = response.country.isoCode
        cache[ip] = country
        return country
    }

    fun isChinaIP(ip: ByteArray): Boolean {
        if (getIPCountry(ip) == "CN") return true
        return false
    }
}