using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IPABan
{
    public class Configuration
    {
        public int banDuration = 3600;
        public string IPDBapiKey = "";
        public int attemptPermaBan = 3;
        public int attempBeforeBan = 5;
        public int debugLevel = 0;
        public string[] filterIp = { "10.0.0.*", "127.0.0.1" };
    }
}
