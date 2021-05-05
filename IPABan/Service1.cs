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
using Formatting = Newtonsoft.Json.Formatting;
using System.Net;

namespace IPABan
{
    public partial class Service1 : ServiceBase
    {

        public static List<String> LogProcess = new List<string>();
        public static List<String> ErrorProcess = new List<string>();

        class BannedIP
        {
            public IAddress ipAddress;
            public long expire;
        }

        



        List<IPDBApi.ipStat> ipAttempt = new List<IPDBApi.ipStat>();
        List<BannedIP> bannedIPList = new List<BannedIP>();

        public Service1()
        {
            InitializeComponent();
        }


        void BanIP(IAddress _ip, int _expire)
        {
            foreach(BannedIP b in bannedIPList)
            {
                if(b.ipAddress == _ip)
                {
                    return;
                }
            }
            
            BannedIP ban = new BannedIP();
            ban.ipAddress = _ip;
            ban.expire = _expire;
            bannedIPList.Add(ban);
            WriteLog("Banning");
        }


        protected override void OnStart(string[] args)
        {
            WriteToFile("Service is started. " + DateTime.Now);          
            FindRule();
            RegisterListener();
            Thread trd = new Thread(new ThreadStart(this.FirewallUpdater));
            trd.IsBackground = true;
            trd.Start();


            Thread LogThread = new Thread(new ThreadStart(this.ThreadLog));
            LogThread.IsBackground = true;
            LogThread.Start();

            WriteError("Test");
        }
        protected override void OnStop()
        {
            WriteToFile("Service stopped. " + DateTime.Now);
        }


        #region Threads
        void FirewallUpdater()
        {
            while (true)
            {
                try
                {
                    Thread.Sleep(1000);

                    //string json = JsonConvert.SerializeObject(bannedIPList, Formatting.Indented);

                    //WriteLog(json.ToString());
                    List<BannedIP> ban = bannedIPList;

                    foreach (BannedIP ip in ban)
                    {
                        if (ip.expire != -1)
                        {
                            if (ip.expire - (Int32)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds <= 0)
                            {
                                WriteLog("unban ip : " + ip.ipAddress);
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
                    WriteError(e.Source);
                }
            }
        }
        void CheckThread(string ipAddress)
        {
            try
            {
                if (!IPDBApi.CheckIP(ipAddress))
                {
                    ipAttempt[FindIP(ipAddress.ToString())].banAmount++;
                    BanIP(SingleIP.Parse(ipAddress), (Int32)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + Config.banDuration);


                    WriteLog("Banning from DB IP : " + ipAddress);
                    FirewallUpdate();
                }
                else
                {
                    //WriteLog("IP Trusted");
                }
            }
            catch (Exception e)
            {
                WriteError(e.Message);
            }

        }
        void ThreadLog()
        {
            WriteToFile("Stating threadlog");
            while (true)
            {
                Thread.Sleep(100);

                try
                {
                    if (LogProcess.Count > 0)
                    {
                        WriteToFile(LogProcess[0]);
                        LogProcess.RemoveAt(0);

                    }
                }
                catch (Exception e)
                {
                    ErrorWriter(e.Message);
                    ErrorWriter("#89");
                }

                try
                {

                    if (ErrorProcess.Count > 0)
                    {

                        ErrorWriter(ErrorProcess[0]);
                        ErrorProcess.RemoveAt(0);

                    }
                }
                catch (Exception e)
                {
                    ErrorWriter(e.Message);
                    ErrorWriter("#88");
                }
            }
        }
        #endregion
       
        #region Writers
        public static void WriteLog(string _string)
        {
            LogProcess.Add(_string);            
        }

        public static void WriteError(string _string)
        {
            ErrorProcess.Add(_string);
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

        public static void ErrorWriter(string text)
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
        #endregion


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
                                        WriteLog("Connection attempts with IP : " + ipAddress);
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
                                                if(ipAttempt[idxIP].banAmount >= Config.attemptPermaBan)
                                                {
                                                    ipAttempt[idxIP].banAmount++;
                                                    BanIP(SingleIP.Parse(ipAttempt[idxIP].ip), -1);   
                                                }
                                                else
                                                {
                                                    ipAttempt[idxIP].banAmount++;
                                                    BanIP(SingleIP.Parse(ipAttempt[idxIP].ip), (Int32)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + Config.banDuration);
                                                }      
                                                //Report ip if never reported
                                                if(!ipAttempt[idxIP].check)
                                                {
                                                    var Reporter = new Thread(() => IPDBApi.ReportIP(ipAddress, "Windows login attemp failed " + ipAttempt[idxIP].attemptCount.ToString() + " times."));
                                                    Reporter.Start();
                                                }
                                            }
                                        }
                                        WriteLog("Attemps : " + ipAttempt[idxIP].attemptCount.ToString());
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
                    WriteLog("Banned count : " + bannedIPList.Count);
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

        #region Finders

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

        #endregion





        void RegisterListener()
        {
            string watchLog = "Security";
            EventLog myLog = new EventLog(watchLog);
            myLog.EntryWritten += new EntryWrittenEventHandler(OnEntryWritten);
            myLog.EnableRaisingEvents = true;
        }

       
    }
}
