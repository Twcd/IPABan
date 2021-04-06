using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Xml;
using System.ServiceProcess;
using System.Collections.Generic;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using System.Threading;
using RestSharp;
using Newtonsoft.Json;

namespace IPABan
{
    public partial class Service1 : ServiceBase
    {
        #region JSONClass
        public class Report
        {
            public DateTime reportedAt { get; set; }
            public string comment { get; set; }
            public IList<int> categories { get; set; }
            public int reporterId { get; set; }
            public string reporterCountryCode { get; set; }
            public string reporterCountryName { get; set; }
        }

        public class Data
        {
            public string ipAddress { get; set; }
            public bool isPublic { get; set; }
            public int ipVersion { get; set; }
            public bool? isWhitelisted { get; set; }
            public int abuseConfidenceScore { get; set; }
            public string countryCode { get; set; }
            public string usageType { get; set; }
            public string isp { get; set; }
            public string domain { get; set; }
            public IList<object> hostnames { get; set; }
            public string countryName { get; set; }
            public int totalReports { get; set; }
            public int numDistinctUsers { get; set; }
            public DateTime? lastReportedAt { get; set; }
            public IList<Report> reports { get; set; }
        }

        public class CheckIPRequest
        {
            public Data data { get; set; }
        }

        class ipStat
        {
            public int attemptCount;
            public long timeStamp;
            public string ip;
        }

        public class Meta
        {
            public DateTime generatedAt { get; set; }
        }

        public class Datum
        {
            
            public string ipAddress { get; set; }
            public string countryCode { get; set; }
            public int abuseConfidenceScore { get; set; }
            public DateTime lastReportedAt { get; set; }
        }

        public class BlackListIPRequest
        {
            public Meta meta { get; set; }
            public IList<Datum> data { get; set; }
        }

        #endregion
        class BannedIP
        {
            public IAddress ipAddress;
            public long expire;
        }



 const string APIKey = "";



        List<ipStat> ipAttempt = new List<ipStat>();
        List<BannedIP> bannedIPList = new List<BannedIP>();

        public Service1()
        {
            InitializeComponent();
        }

        void CheckThread(string ipAddress)
        {
            try
            {
                WriteToFile("Creating thread for IP check");
                if (!CheckIP(ipAddress))
                {
                    BannedIP ban = new BannedIP();
                    ban.ipAddress = SingleIP.Parse(ipAddress);
                    ban.expire = DateTime.Now.ToFileTime() + Config.banDuration;

                    bannedIPList.Add(ban);
                    WriteToFile("Banning from DB IP : " + ipAddress);
                    FirewallUpdate();
                }
                else
                {
                    WriteToFile("IP Trusted");
                }
            }
            catch(Exception e)
            {
                WriteError(e.Message);
            }
          
        }

        //Return true if IP was not reported more than 3 times.
        bool CheckIP(string _ip)
        {
            try
            {

                var client = new RestClient("https://api.abuseipdb.com/api/v2/check");
                var request = new RestRequest(Method.GET);
                request.AddHeader("Key", APIKey);
                request.AddHeader("Accept", "application/json");
                request.AddParameter("ipAddress", _ip);
                request.AddParameter("maxAgeInDays", "90");
                request.AddParameter("verbose", "");

                IRestResponse response = client.Execute(request);               
                var json = JsonConvert.DeserializeObject<CheckIPRequest>(response.Content);
               
                if(json.data.totalReports >= 3)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            catch(Exception e)
            {
                WriteError("#3");
                WriteError(e.Message);
                return true;
            
            }
        }


        protected override void OnStart(string[] args)
        {
            WriteToFile("Service is started. " + DateTime.Now);

            //BanBlackList();
            FindRule();
            RegisterListener();
            Thread trd = new Thread(new ThreadStart(this.FirewallUpdater));
            trd.IsBackground = true;
            trd.Start();

            

        }



        string GetBlackList()
        {
            var client = new RestClient("https://api.abuseipdb.com/api/v2/blacklist");
            var request = new RestRequest(Method.GET);
            request.AddHeader("Key", APIKey);
            request.AddHeader("Accept", "application/json");
            request.AddParameter("confidenceMinimum", "90");

            IRestResponse response = client.Execute(request);

            dynamic parsedJson = JsonConvert.DeserializeObject(response.Content);

            foreach (var item in parsedJson)
            {
                Console.WriteLine(item);
            }

            return response.Content;
        }


        void FirewallUpdater()
        {
            try
            {         
                while(true)
                {
                    Thread.Sleep(6000);
                    foreach(BannedIP ip in bannedIPList)
                    {
                        if(ip.expire >= DateTime.Now.ToFileTime())
                        {
                            bannedIPList.Remove(ip);
                            FirewallUpdate();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                WriteError("#1");
                WriteError(e.Message);
            }
        }

        private void OnEntryWritten(object source, EntryWrittenEventArgs e)
        {
          
            string watchLog = "Security";
            string logName = watchLog;
            int e1 = 0;
            EventLog log = new EventLog(logName);

            e1 = log.Entries.Count - 1; // last entry

            if (log.Entries[e1].InstanceId == 4625)
            {
                string query = @"*[System[(EventID = 4625)]]";
                EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, query);
                try
                {
                    eventsQuery.ReverseDirection = true;
                    EventLogReader logReader = new EventLogReader(eventsQuery);

                    //WriteToFile("Description : " + logReader.ReadEvent().ToXml());
                    XmlReader reader = XmlReader.Create(new StringReader(logReader.ReadEvent().ToXml()));
                    while (reader.Read())
                    {
                        if (reader.IsStartElement())
                        {
                            //WriteToFile(reader.Name + ":" + reader.Value);
                            switch (reader.Name.ToString())
                            {
                                case "Data":
                                    if (reader.GetAttribute(0) == "TargetUserName")
                                    {
                                        WriteToFile("Connection attemps with username : " + reader.ReadElementContentAsString());

                                    }
                                    if (reader.GetAttribute(0) == "IpAddress")
                                    {

                                        string ipAddress = reader.ReadElementContentAsString();
                                        WriteToFile(ipAddress);


                                        var t = new Thread(() => CheckThread(ipAddress));
                                        t.Start();
                                       


                                        int idxIP = FindIP(ipAddress);
                                        if (idxIP == -1)
                                        {
                                            ipStat newStat = new ipStat();
                                            newStat.timeStamp = DateTime.Now.ToFileTime();
                                            newStat.ip = ipAddress;
                                            newStat.attemptCount = 1;
                                            ipAttempt.Add(newStat);
                                        }
                                        else
                                        {

                                            ipAttempt[idxIP].attemptCount++;
                                            if (ipAttempt[idxIP].attemptCount >= 5)
                                            {
                                                IRule rule1 = FindRule();

                                                BannedIP ban = new BannedIP();
                                                ban.ipAddress = SingleIP.Parse(ipAddress);
                                                ban.expire = DateTime.Now.ToFileTime() + Config.banDuration;
                                                bannedIPList.Add(ban);
                                                WriteToFile("Banning");
                                            }
                                        }
                                        WriteToFile("Attemps : " + ipAttempt[idxIP].attemptCount.ToString());
                                        FirewallUpdate();

                                    }
                                    break;
                            }
                        }
                    }
                }
                catch (EventLogNotFoundException)
                {
                    WriteError("Error while reading the event logs");
                    return;
                }
            }
        }


        void FirewallUpdate()
        {
            try
            {      
                //WriteToFile("Updating firewall rule...");
                IRule ruledel = FindRule();         
            
            
                if(ruledel != null)
                {
                    FirewallManager.Instance.Rules.Remove(ruledel);
                }

                var rule = FirewallManager.Instance.CreateApplicationRule(
                      FirewallManager.Instance.GetProfile().Type,
                      @"IPABan",
                      FirewallAction.Block,
                      null
                 );
                rule.Direction = FirewallDirection.Inbound;
                rule.LocalPorts = new ushort[] { 3389 };
                rule.Action = FirewallAction.Block;
                rule.Protocol = FirewallProtocol.Any;
                rule.Scope = FirewallScope.All;
                rule.Profiles = FirewallProfiles.Public | FirewallProfiles.Private;
                IAddress[] banList;


                if (bannedIPList.Count == 0)
                {
                    banList = new IAddress[1];
                    banList[0] = SingleIP.Parse("1.1.1.1");
                }
                else
                {
                    WriteToFile("Banned count : " + bannedIPList.Count);
                    banList = new IAddress[bannedIPList.Count];
                    int i = 0;
                  //  WriteToFile("===================================");
                    foreach (BannedIP banned in bannedIPList)
                    {
                        
                        //WriteToFile("I Value : " + i);
                        //WriteToFile("IP : " + banned.ipAddress);
                        //WriteToFile("---------------------------------------");
                        banList[i] = banned.ipAddress;
                        i++;
                    }
                    //WriteToFile("===================================");
                }          
                rule.RemoteAddresses = banList;
                FirewallManager.Instance.Rules.Add(rule);
            }
            catch (Exception e)
            {
                WriteError("#2");
                WriteError(e.Message);
            }
        }

        IRule FindRule()
        {
            try
            {


                foreach (IRule rule in FirewallManager.Instance.Rules)
                {
                    if (rule.Name == "IPABan")
                    {
                        return rule;
                    }
                }
                return null;
            }
            catch (Exception e)
            {
                WriteError(e.Message);
                return null;
            }
                }

        int FindIP(string _ip)
        {
            foreach (ipStat ip in ipAttempt)
            {
                if (ip.ip == _ip)
                {
                    return ipAttempt.IndexOf(ip);
                }
            }
            return -1;
        }

        public static void WriteToFile(string text)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\Logs";
            string ext = ".txt";
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            string filePath = path + "\\ServiceLog" + DateTime.Now.Date.ToShortDateString().Replace("/", "_") + ext;


            if (!File.Exists(filePath))
            {
                using (StreamWriter sw = File.CreateText(filePath))
                {
                    sw.WriteLine(text);
                }
            }
            else
            {
                using (StreamWriter sw = File.AppendText(filePath))
                {
                    sw.WriteLine(text);
                }
            }

        }

        public static void WriteError(string text)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\Logs";
            string ext = ".txt";
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            string filePath = path + "\\ServiceError" + DateTime.Now.Date.ToShortDateString().Replace("/", "_") + ext;


            if (!File.Exists(filePath))
            {
                using (StreamWriter sw = File.CreateText(filePath))
                {
                    sw.WriteLine(text);
                }
            }
            else
            {
                using (StreamWriter sw = File.AppendText(filePath))
                {
                    sw.WriteLine(text);
                }
            }
        }



        void RegisterListener()
        {
            string watchLog = "Security";
            EventLog myLog = new EventLog(watchLog);
            myLog.EntryWritten += new EntryWrittenEventHandler(OnEntryWritten);
            myLog.EnableRaisingEvents = true;
        }

        protected override void OnStop()
        {
            WriteToFile("Service stopped. " + DateTime.Now);
        }
    }
}
