package libs.geoIP

import com.maxmind.geoip2.DatabaseReader
import com.maxmind.geoip2.exception.AddressNotFoundException
import com.maxmind.geoip2.model.CityResponse
import java.io.File
import java.net.InetAddress
import kotlin.collections.HashMap


class GeoIP(filePath: String?) {
    private lateinit var dataBaseFile: File
    private var reader: DatabaseReader?
    private val cache = HashMap<String, String>()

    init {
        reader = null
        if (filePath != null) {
            dataBaseFile = File(filePath)
            if (dataBaseFile.exists()) reader = DatabaseReader.Builder(dataBaseFile).build()
        }
    }

    fun getIPCountry(rawIP: ByteArray): String? {
        if (reader == null) return null

        val ip = InetAddress.getByAddress(rawIP).hostAddress
        if (cache.containsKey(ip)) return cache[ip]

        val response: CityResponse
        try {
            response = reader!!.city(InetAddress.getByAddress(rawIP))
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