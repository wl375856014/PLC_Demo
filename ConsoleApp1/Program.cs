using Newtonsoft.Json;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            String JSON = "";
            List<Config> list = JsonConvert.DeserializeObject<List<Config>>(JSON);
            list.ForEach(x =>
            {
                Task.Run(() => x.ConnectAsync());
            });
        }
    }

    public class Config
    {
        /// <summary>
        /// opcua服务地址
        /// </summary>
        public string ServerUrl { get; set; } = "opc.tcp://10.60.25.2:4840";

        /// <summary>
        /// opcua服务器用户名
        /// </summary>
        public string UserName { get; set; } = "yd0484";

        /// <summary>
        /// opcua服务器密码
        /// </summary>
        public string Password { get; set; } = "yd123456";

        /// <summary>
        /// PLC描述
        /// </summary>
        public string DescName { get; set; } = "1防区-1股道-1列为";
    }

    public static class PLC
    {
        public static Boolean Online = false;

        public static UAClient Client;

        /// <summary>
        /// 连接PLC
        /// </summary>
        public static async void ConnectAsync(this Config config)
        {
            if (Client == null) Client = new UAClient();
            Online = await Client.ConnectAsync(config);//链接PLC
            //Write log
            if (!Online) return;

            Client.SubscribeToDataChanges(PLCNodesType.Nodes.Values.ToList());//订阅PLC节点

            //PLC session 通知事件
            Client.Session.Notification += (session, e) =>
            {
                NotificationMessage message = e.NotificationMessage;
                foreach (var monitoredItemNotification in message.GetDataChanges(false))
                {
                    MonitoredItem item = e.Subscription.FindItemByClientHandle(monitoredItemNotification.ClientHandle);
                    if (item == null) continue;

                    var nodeId = PLCNodesType.ns + item.StartNodeId.Identifier.ToString();
                    var value = monitoredItemNotification.Value.Value;
                    if (value == null) continue;

                    byte[] bytes = (byte[])value;
                    try
                    {
                        switch (nodeId)
                        {
                            case PLCNodesType.Isolation: // 隔离开关
                                //foreach (var (i, v) in positions.Select((i, v) => (v, i)))
                                //{
                                //    v.State.Isolation = bytes[i];
                                //}
                                break;
                            case PLCNodesType.ElecResult: // 验电装置
                                //foreach (var (i, v) in positions.Select((i, v) => (v, i)))
                                //{
                                //    v.State.ElecResult = bytes[i];
                                //}
                                break;
                            case PLCNodesType.HasTrain: // 有无车
                                //foreach (var (i, v) in positions.Select((i, v) => (v, i)))
                                //{
                                //    bool hasTrain = bytes[i] == 1;
                                //    bool oldHasTrain = v.State.Trains?.FirstOrDefault() != null;
                                //    if (hasTrain && !oldHasTrain) // 无车到有车
                                //    {
                                //        int no = 0;
                                //        var algorithmReq = new AlgorithmDetectRequest(DetectType.Train, MethodType.Stream, default, v.Videos.First(f => f.Type == VideoType.TrainNumeber).Url);
                                //        var algorithmRsp = algorithmReq.Request<ResponseData<DetectData>>();
                                //        if (algorithmRsp != null && algorithmRsp.IsSuccess && algorithmRsp.Data != null)
                                //        {
                                //            no = algorithmRsp.Data.Result;
                                //        }

                                //        v.State.Trains = new List<Train?>() { new Train() { No = no.ToString() } };
                                //    }
                                //    else if (!hasTrain && oldHasTrain) // 有车到无车
                                //    {
                                //        v.State.Trains = new List<Train?>() { null };
                                //    }
                                //}
                                break;
                            case PLCNodesType.Invade: // 列车接近
                                //foreach (var (i, v) in positions.Select((i, v) => (v, i)))
                                //{
                                //    v.State.Warning = bytes[i];
                                //}
                                break;
                            default:
                                throw new ArgumentException();
                        }
                    }
                    catch (Exception ex)
                    {
                        //write log
                    }
                }
            };
        }
    }

    public class UAClient
    {
        private ApplicationConfiguration m_configuration;

        private Session m_session;

        private readonly Action<IList, IList> m_validateResponse;

        public ShowMonitoredItemNotification ReceiveMsg;

        /// <summary>
        /// session.
        /// </summary>
        public Session Session => m_session;

        /// <summary>
        /// session名称
        /// </summary>
        public string SessionName { get; set; } = "DefaultSession";

        /// <summary>
        /// 配置文件
        /// </summary>
        public string ConfigPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "Config\\Opc.Ua.SafetyProducts.Config.xml");

        /// <summary>
        /// 日志委托
        /// </summary>
        public Action<string> LogAction { get; set; } = msg => { Console.Write(msg); };

        /// <summary>
        /// 订阅委托
        /// </summary>
        /// <param name="DisplayName"></param>
        /// <param name="Value"></param>
        public delegate void ShowMonitoredItemNotification(string DisplayName, string Value);

        /// <summary>
        /// ctor
        /// </summary>
        public UAClient()
        {
            ApplicationInstance application = new ApplicationInstance();
            application.ApplicationName = SessionName;
            application.ApplicationType = ApplicationType.Client;

            application.LoadApplicationConfiguration(ConfigPath, silent: false).Wait();//加载配置文件

            //检查申请证书.
            application.CheckApplicationInstanceCertificate(silent: false, minimumKeySize: 0).Wait();
            m_validateResponse = ClientBase.ValidateResponse;
            m_configuration = application.ApplicationConfiguration;
            m_configuration.CertificateValidator.CertificateValidation += CertificateValidation;
            ReceiveMsg += Msg;
        }

        /// <summary>
        /// 连接服务器
        /// </summary>
        public async Task<bool> ConnectAsync(Config config)
        {
            try
            {
                if (m_session != null && m_session.Connected == true) LogAction?.Invoke("会话已连接！");
                else
                {
                    LogAction?.Invoke("连接...");

                    //通过连接到服务器的发现终结点来获取终结点。
                    //尝试在没有安全性的情况下查找第一个内点。
                    EndpointDescription endpointDescription = CoreClientUtils.SelectEndpoint(config.ServerUrl, false);

                    EndpointConfiguration endpointConfiguration = EndpointConfiguration.Create(m_configuration);
                    ConfiguredEndpoint endpoint = new ConfiguredEndpoint(null, endpointDescription, endpointConfiguration);

                    //创建会话
                    Session session = await Session.Create(m_configuration, endpoint, false, false,
                        m_configuration.ApplicationName, 30 * 60 * 1000,
                        new UserIdentity(config.UserName, config.Password), null);

                    //分配创建的会话
                    if (session != null && session.Connected)
                    {
                        m_session = session;
                    }

                    //已成功创建会话
                    //LogAction?.Invoke($"New Session Created with SessionName = {m_session.SessionName}");
                    LogAction?.Invoke($"{config.DescName}-{config.ServerUrl}已连接");
                }

                return true;
            }
            catch (Exception ex)
            {
                //日志错误
                //LogAction?.Invoke($"Create Session Error : {ex.Message}");
                LogAction?.Invoke($"{config.DescName}-{config.ServerUrl}未连接，{ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 断开链接
        /// </summary>
        public void Disconnect()
        {
            try
            {
                if (m_session != null)
                {
                    LogAction?.Invoke("Disconnecting...");

                    m_session.Close();
                    m_session.Dispose();
                    m_session = null;

                    // Log Session Disconnected event
                    LogAction?.Invoke("Session Disconnected.");
                }
                else
                {
                    LogAction?.Invoke("Session not created!");
                }
            }
            catch (Exception ex)
            {
                // Log Error
                LogAction?.Invoke($"Disconnect Error : {ex.Message}");
            }
        }

        /// <summary>
        /// 读单个节点
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="location">ns=4;s=A_AGV到周转桶</param>
        /// <returns>ns=0;i=2255 查看所有命名空间</returns>
        public T ReadNode<T>(string location)
        {
            if (m_session == null || m_session.Connected == false)
            {
                throw new Exception("连接已断开");
            }
            var value = m_session.ReadValue(location);
            return (T)value.Value;
        }

        /// <summary>
        /// 读多个节点
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="locations"></param>
        /// <returns></returns>
        public List<T> ReadNodes<T>(List<string> locations)
        {
            if (m_session == null || m_session.Connected == false)
            {
                throw new Exception("连接已断开");
            }
            var typeList = new List<Type>();
            foreach (var location in locations)
            {
                typeList.Add(typeof(T));
            }
            var nodeIds = locations.Select(t => new NodeId(t)).ToList();
            m_session.ReadValues(nodeIds, typeList, out List<object> values, out List<ServiceResult> errors);
            return values.Select(t => (T)t).ToList();
        }

        /// <summary>
        /// 写单个节点
        /// </summary>
        /// <param name="location"></param>
        /// <param name="value"></param>
        public void WriteNode(string location, object value)
        {
            if (m_session == null || m_session.Connected == false)
            {
                throw new Exception("连接已断开");
            }
            WriteValueCollection nodesToWrite = new WriteValueCollection();
            WriteValue intWriteVal = new WriteValue();
            intWriteVal.NodeId = new NodeId(location);
            intWriteVal.AttributeId = Attributes.Value;
            intWriteVal.Value = new DataValue();
            intWriteVal.Value.Value = value;
            nodesToWrite.Add(intWriteVal);
            m_session.Write(null,
                            nodesToWrite,
                            out StatusCodeCollection results,
                            out DiagnosticInfoCollection diagnosticInfos);
        }

        /// <summary>
        /// 写多个节点
        /// </summary>
        /// <param name="locations"></param>
        /// <param name="values"></param>
        public void WriteNodes(List<string> locations, List<object> values)
        {
            if (m_session == null || m_session.Connected == false)
            {
                throw new Exception("连接已断开");
            }
            WriteValueCollection nodesToWrite = new WriteValueCollection();
            for (int i = 0; i < locations.Count; i++)
            {
                WriteValue intWriteVal = new WriteValue();
                intWriteVal.NodeId = new NodeId(locations[i]);
                intWriteVal.AttributeId = Attributes.Value;
                intWriteVal.Value = new DataValue();
                intWriteVal.Value.Value = values[i];
                nodesToWrite.Add(intWriteVal);
            }
            m_session.Write(null, nodesToWrite, out StatusCodeCollection results, out DiagnosticInfoCollection diagnosticInfos);
        }

        /// <summary>
        ///订阅多个节点
        /// </summary>
        public void SubscribeToDataChanges(List<string> locations)
        {
            if (m_session == null || m_session.Connected == false)
            {
                throw new Exception("连接已断开");
            }
            try
            {
                // 创建订阅以接收数据更改通知，定义订阅参数
                Subscription subscription = new Subscription(m_session.DefaultSubscription);

                subscription.DisplayName = "Console ReferenceClient Subscription";
                subscription.PublishingEnabled = true;
                subscription.PublishingInterval = 1000;

                m_session.AddSubscription(subscription);

                //在服务器端创建订阅
                subscription.Create();

                foreach (string loa in locations)
                {
                    MonitoredItem intMonitoredItem = new MonitoredItem(subscription.DefaultItem);
                    // Int32 Node - Objects\CTT\Scalar\Simulation\Int32
                    intMonitoredItem.StartNodeId = new NodeId(loa);
                    intMonitoredItem.AttributeId = Attributes.Value;
                    intMonitoredItem.DisplayName = loa;
                    intMonitoredItem.SamplingInterval = 1000;
                    intMonitoredItem.Notification += OnMonitoredItemNotification;
                    subscription.AddItem(intMonitoredItem);
                }
                // 在服务器端创建监控项
                subscription.ApplyChanges();
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private void Msg(string DisplayName, string Value)
        {

        }

        /// <summary>
        /// 新通知到达时通知
        /// </summary>
        /// <param name="monitoredItem"></param>
        /// <param name="e"></param>
        /// <exception cref="Exception"></exception>
        private void OnMonitoredItemNotification(MonitoredItem monitoredItem, MonitoredItemNotificationEventArgs e)
        {
            try
            {
                // Log MonitoredItem Notification event
                MonitoredItemNotification notification = e.NotificationValue as MonitoredItemNotification;
                ReceiveMsg(monitoredItem.DisplayName, notification.Value.ToString());
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        /// <summary>
        /// 处理证书验证事件。 每次从服务器接收到不受信任的证书时，都会触发此事件。
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void CertificateValidation(CertificateValidator sender, CertificateValidationEventArgs e)
        {
            bool certificateAccepted = true;

            // ****
            // Implement a custom logic to decide if the certificate should be
            // accepted or not and set certificateAccepted flag accordingly.
            // The certificate can be retrieved from the e.Certificate field
            // ***

            ServiceResult error = e.Error;
            while (error != null)
            {
                LogAction?.Invoke(error.ToString());
                error = error.InnerResult;
            }

            if (certificateAccepted)
            {
                LogAction?.Invoke($"Untrusted Certificate accepted. SubjectName = {e.Certificate.SubjectName}");
            }

            e.AcceptAll = certificateAccepted;
        }
    }

    public class PLCNodesType
    {
        public const string ns = "ns=6;s=";
        public const string Isolation = ns + "::AsGlobalPV:State_QS";
        public const string ElecResult = ns + "::AsGlobalPV:Result_Elsc";
        public const string HasTrain = ns + "::AsGlobalPV:Port_Train";
        public const string Invade = ns + "::AsGlobalPV:Cmd_Invade";

        //public const string 
        public static Dictionary<string, string> Nodes;

        static PLCNodesType()
        {
            Nodes = new Dictionary<string, string>();
            Nodes.Add(nameof(Isolation), Isolation);
            Nodes.Add(nameof(ElecResult), ElecResult);
            Nodes.Add(nameof(HasTrain), HasTrain);
            Nodes.Add(nameof(Invade), Invade);
        }
    }
}
