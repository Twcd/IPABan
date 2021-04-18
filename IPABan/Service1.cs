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
       
 

        class BannedIP
        {
            public IAddress ipAddress;
            public long expire;
        }



        //TODO: Ajouter dans IP attempt si l'ip a deja etait checker sur la BD et ne pas refaire une verification si sa a deja etait fait il y'a moins de X temps.

        List<IPDBApi.ipStat> ipAttempt = new List<IPDBApi.ipStat>();
        List<BannedIP> bannedIPList = new List<BannedIP>();

        public Service1()
        {
            InitializeComponent();
        }



        void CheckThread(string ipAddress)
        {
            try
            {
                if (!IPDBApi.CheckIP(ipAddress))
                {
                    BannedIP ban = new BannedIP();
                    ban.ipAddress = SingleIP.Parse(ipAddress);
                    ban.expire = (Int32)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + Config.banDuration;
                    ipAttempt[FindIP(ban.ipAddress.ToString())].banAmount++;
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
        


        protected override void OnStart(string[] args)
        {
            WriteToFile("Service is started. " + DateTime.Now);
            //IPDBApi.ReportIP("127.0.0.1", "IDK Why");
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
            request.AddHeader("Key", Config.apiKey);
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
            while (true)
            {
                try
                {

                    Thread.Sleep(1000);
                    List<BannedIP> ban = bannedIPList;
                    foreach (BannedIP ip in ban)
                    {
                        if(ip.expire != -1)
                        {
                            if (ip.expire - (Int32)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds <= 0)
                            {
                                WriteToFile("unban ip : " + ip.ipAddress);
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
                                       // WriteToFile("Connection attemps with username : " + reader.ReadElementContentAsString());

                                    }
                                    if (reader.GetAttribute(0) == "IpAddress")
                                    {                                       
                                        string ipAddress = reader.ReadElementContentAsString();
                                        WriteToFile("Connection attempts with IP : " + ipAddress);
                                        var t = new Thread(() => CheckThread(ipAddress));
                                        t.Start();
                                       


                                        int idxIP = FindIP(ipAddress);
                                        if (idxIP == -1)
                                        {
                                            IPDBApi.ipStat newStat = new IPDBApi.ipStat();
                                            newStat.timeStamp = (Int32)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                                            newStat.ip = ipAddress;
                                            newStat.attemptCount = 1;
                                            newStat.banAmount++;
                                            ipAttempt.Add(newStat);
                                        }
                                        else
                                        {
                                            ipAttempt[idxIP].attemptCount++;
                                            if (ipAttempt[idxIP].attemptCount >= 5)
                                            {
                                                if(ipAttempt[idxIP].banAmount == Config.attemptPermaBan)
                                                {
                                                    ipAttempt[idxIP].banAmount++;
                                                    BannedIP ban = new BannedIP();
                                                    ban.ipAddress = SingleIP.Parse(ipAddress);
                                                    ban.expire = -1;
                                                    bannedIPList.Add(ban);
                                                    WriteToFile("Banning");
                                                    var Reporter = new Thread(() => IPDBApi.ReportIP(ipAddress, "Windows login attemp failed " + ipAttempt[idxIP].attemptCount.ToString() + " times."));
                                                    Reporter.Start();
                                                }
                                                else
                                                {
                                                    ipAttempt[idxIP].banAmount++;
                                                    BannedIP ban = new BannedIP();
                                                    ban.ipAddress = SingleIP.Parse(ipAddress);
                                                    ban.expire = (Int32)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + Config.banDuration;
                                                    bannedIPList.Add(ban);
                                                    WriteToFile("Banning");
                                                    var Reporter = new Thread(() => IPDBApi.ReportIP(ipAddress, "Windows login attemp failed " + ipAttempt[idxIP].attemptCount.ToString() + " times."));
                                                    Reporter.Start();
                                                }                                               
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
                List<IRule> ruledel = FindRule();         
            
            
                if(ruledel != null)
                {
                    foreach(IRule r in ruledel)
                    {
                        FirewallManager.Instance.Rules.Remove(r);
                    }                    
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
                  
                    foreach (BannedIP banned in bannedIPList)
                    {                        
                        banList[i] = banned.ipAddress;
                        i++;
                    }
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

        List<IRule> FindRule()
        {
            List<IRule> ruleList = new List<IRule>();

            try
            {


                foreach (IRule rule in FirewallManager.Instance.Rules)
                {
                    if (rule.Name == "IPABan")
                    {
                        ruleList.Add(rule);
                    }
                }
                if(ruleList.Count == 0)
                {
                    return null;
                }
                else
                {
                    return ruleList;
                }
                
            }
            catch (Exception e)
            {
                WriteError(e.Message);
                return null;
            }
                }

        int FindIP(string _ip)
        {
            foreach (IPDBApi.ipStat ip in ipAttempt)
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
