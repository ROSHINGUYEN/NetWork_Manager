/* =========================================================================
   Giao diện Quản Trị Cổng Mạng LAN - Chuẩn phong cách Viettel Home Gateway
   Pure Vanilla JavaScript - Không dùng framework nặng, hỗ trợ WebSocket realtime
   ========================================================================= */

(() => {
  "use strict";

  // State quản lý toàn bộ dữ liệu giao diện
  const state = {
    devices: [],
    events: [],
    network: {},
    stats: {},
    trafficHistory: [],
    connections: [],
    packets: [],
    securityEvents: [],
    labs: [],
    ispInfo: null,
    adapterInfo: null,
    filter: "all",
    searchQuery: "",
    editingMac: null,
    editingType: "other",
    isIpMasked: true,
    isShieldActive: false,
    shieldCountdownTimer: null,
    shieldSecondsLeft: 3,
  };

  // Cache các phần tử DOM
  const el = {
    // Header & Status
    topInternetStatus: document.getElementById("top-internet-status"),
    topWsStatus: document.getElementById("top-ws-status"),
    systemClock: document.getElementById("system-clock"),
    gatewayModelText: document.getElementById("gateway-model-text"),
    topShieldIndicator: document.getElementById("top-shield-indicator"),
    topShieldText: document.getElementById("top-shield-text"),

    // Router Tabs
    tabNavItems: Array.from(document.querySelectorAll(".nav-tab-item")),
    tabDevices: document.getElementById("tab-devices"),
    tabTraffic: document.getElementById("tab-traffic"),
    tabEvents: document.getElementById("tab-events"),
    tabConnections: document.getElementById("tab-connections"),
    tabSecurity: document.getElementById("tab-security"),
    tabLab: document.getElementById("tab-lab"),
    quickOnlineCount: document.getElementById("quick-online-count"),
    quickTotalCount: document.getElementById("quick-total-count"),

    // Metric Summary Cards
    cardInternetVal: document.getElementById("card-internet-val"),
    cardInternetSub: document.getElementById("card-internet-sub"),
    cardGatewayVal: document.getElementById("card-gateway-val"),
    cardSubnetSub: document.getElementById("card-subnet-sub"),
    cardDevicesVal: document.getElementById("card-devices-val"),
    cardDevicesSub: document.getElementById("card-devices-sub"),
    cardTrafficVal: document.getElementById("card-traffic-val"),
    cardTrafficIface: document.getElementById("card-traffic-iface"),

    // Tab 1: Thiết bị & Quét dải IP & Bảo vệ IP
    scanRangeInput: document.getElementById("scan-range-input"),
    btnScan: document.getElementById("btn-scan"),
    scanLabel: document.getElementById("scan-label"),
    btnToggleIpMask: document.getElementById("btn-toggle-ip-mask"),
    ipMaskIcon: document.getElementById("ip-mask-icon"),
    ipMaskLabel: document.getElementById("ip-mask-label"),
    btnTestShield: document.getElementById("btn-test-shield"),
    filterPills: Array.from(document.querySelectorAll(".pill-btn")),
    countAll: document.getElementById("count-all"),
    countOnline: document.getElementById("count-online"),
    countOffline: document.getElementById("count-offline"),
    searchInput: document.getElementById("search-input"),
    clearSearch: document.getElementById("clear-search"),
    devicesTbody: document.getElementById("devices-tbody"),

    // Tab 2: Băng thông & Thông tin máy chủ
    trafficCanvas: document.getElementById("traffic-canvas"),
    hostHostname: document.getElementById("host-hostname"),
    hostIp: document.getElementById("host-ip"),
    hostGw: document.getElementById("host-gw"),
    hostSubnet: document.getElementById("host-subnet"),
    hostMac: document.getElementById("host-mac"),
    hostUptime: document.getElementById("host-uptime"),

    // Tab 2 V1.3: Adapter Wi-Fi & Ethernet
    adapterBadgeType: document.getElementById("adapter-badge-type"),
    adapterName: document.getElementById("adapter-name"),
    wifiRowSsid: document.getElementById("wifi-row-ssid"),
    wifiSsid: document.getElementById("wifi-ssid"),
    wifiRowBssid: document.getElementById("wifi-row-bssid"),
    wifiBssid: document.getElementById("wifi-bssid"),
    wifiRowSignal: document.getElementById("wifi-row-signal"),
    wifiSignalFill: document.getElementById("wifi-signal-fill"),
    wifiSignalText: document.getElementById("wifi-signal-text"),
    wifiRowRadio: document.getElementById("wifi-row-radio"),
    wifiRadio: document.getElementById("wifi-radio"),
    adapterSpeed: document.getElementById("adapter-speed"),
    adapterDuplexMtu: document.getElementById("adapter-duplex-mtu"),

    // Tab 2 V1.3: Tra cứu ISP & Public IP (Opt-In)
    ispConsentBox: document.getElementById("isp-consent-box"),
    btnLookupIsp: document.getElementById("btn-lookup-isp"),
    ispResultsBox: document.getElementById("isp-results-box"),
    ispPublicIp: document.getElementById("isp-public-ip"),
    ispName: document.getElementById("isp-name"),
    ispAsn: document.getElementById("isp-asn"),
    ispLocation: document.getElementById("isp-location"),
    ispTime: document.getElementById("isp-time"),
    btnRefreshIsp: document.getElementById("btn-refresh-isp"),

    // Tab 3: Nhật ký sự kiện
    eventFeed: document.getElementById("event-feed"),

    // Modal Chỉnh Sửa Tên Thiết Bị
    editModal: document.getElementById("edit-modal"),
    editForm: document.getElementById("edit-form"),
    editMac: document.getElementById("edit-mac"),
    modalDeviceIp: document.getElementById("modal-device-ip"),
    modalDeviceMac: document.getElementById("modal-device-mac"),
    inputCustomName: document.getElementById("input-custom-name"),
    typeSelector: document.getElementById("type-selector"),
    modalClose: document.getElementById("modal-close"),
    modalCancel: document.getElementById("modal-cancel"),

    // Tab 4: Connections & Packets
    connectionsTbody: document.getElementById("connections-tbody"),
    packetsTbody: document.getElementById("packets-tbody"),

    // Tab 5: Security SOC
    securityTbody: document.getElementById("security-tbody"),
    threatInfoCount: document.getElementById("threat-info-count"),
    threatWarnCount: document.getElementById("threat-warn-count"),
    threatCritCount: document.getElementById("threat-crit-count"),

    // Tab 6: Security Lab Mode
    securityLabList: document.getElementById("security-lab-list"),

    // Khiên Đỏ Cảnh Báo Chống Chụp Màn Hình (Anti-Screenshot Red Shield)
    securityScreenshotShield: document.getElementById("security-screenshot-shield"),
    shieldDetectedTime: document.getElementById("shield-detected-time"),
    shieldDetectedReason: document.getElementById("shield-detected-reason"),
    btnUnlockShield: document.getElementById("btn-unlock-shield"),
    shieldCountdown: document.getElementById("shield-countdown"),

    // Toast Container
    toastContainer: document.getElementById("toast-container"),
  };

  const API_BASE = "";

  // -------------------------------------------------------------------------
  // Tiện ích hỗ trợ định dạng dữ liệu & Che giấu IP/MAC (Formatters & Privacy)
  // -------------------------------------------------------------------------

  function maskIpString(ip) {
    if (!ip || ip === "--") return "--";
    const str = String(ip).trim();
    if (str.includes("/")) {
      const parts = str.split("/");
      return `***.***.***.*** /${parts[1]}`;
    }
    if (str.includes(":")) {
      const parts = str.split(":");
      return `***.***.***.***:${parts[1]}`;
    }
    return "***.***.***.***";
  }

  function maskMacString(mac) {
    if (!mac || mac === "--") return "--";
    return "••:••:••:••:••:••";
  }

  function getDisplayHostname(name) {
    if (!name || name === "--") return "--";
    if (state.isIpMasked) {
      return "Host-******";
    }
    return String(name);
  }

  function getDisplayIp(ip) {
    if (!ip || ip === "--") return "--";
    return state.isIpMasked ? maskIpString(ip) : String(ip);
  }

  function formatIp(ip) {
    if (!ip || ip === "--") return "--";
    const raw = String(ip);
    if (state.isIpMasked) {
      return `<span class="ip-masked" title="Địa chỉ IP đã được ẩn bảo mật (Nhấp 'Hiện IP mạng' để mở)" data-raw="${escapeHtml(raw)}">${escapeHtml(maskIpString(raw))}</span>`;
    }
    return `<span class="ip-plain" data-raw="${escapeHtml(raw)}">${escapeHtml(raw)}</span>`;
  }

  function formatMac(mac) {
    if (!mac || mac === "--") return "--";
    const raw = String(mac);
    if (state.isIpMasked) {
      return `<span class="mac-masked" title="Địa chỉ MAC đã được che bảo mật" data-raw="${escapeHtml(raw)}">${escapeHtml(maskMacString(raw))}</span>`;
    }
    return `<span class="mac-plain" data-raw="${escapeHtml(raw)}">${escapeHtml(raw)}</span>`;
  }

  function formatBytes(bytesPerSec) {
    if (bytesPerSec == null || isNaN(bytesPerSec) || bytesPerSec <= 0) return "0 B/s";
    const units = ["B/s", "KB/s", "MB/s", "GB/s"];
    let val = bytesPerSec;
    let idx = 0;
    while (val >= 1024 && idx < units.length - 1) {
      val /= 1024;
      idx++;
    }
    return `${val.toFixed(val >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
  }

  function formatTimeAgo(isoString) {
    if (!isoString) return "--";
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return "--";
    const diffSec = Math.floor((Date.now() - date.getTime()) / 1000);
    if (diffSec < 15) return "Vừa xong";
    if (diffSec < 60) return `${diffSec}s trước`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin} phút trước`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h trước`;
    return date.toLocaleDateString("vi-VN", { hour: "2-digit", minute: "2-digit" });
  }

  function formatUptime(seconds) {
    if (!seconds) return "--";
    const s = Math.floor(seconds);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d} ngày ${h}h`;
    if (h > 0) return `${h} giờ ${m}p`;
    return `${m} phút`;
  }

  function escapeHtml(str) {
    if (str == null) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showToast(message, type = "info") {
    if (!el.toastContainer) return;
    const toast = document.createElement("div");
    toast.className = "toast-msg";
    if (type === "error") {
      toast.style.borderLeftColor = "#DC2626";
    } else if (type === "success") {
      toast.style.borderLeftColor = "#16A34A";
    } else {
      toast.style.borderLeftColor = "var(--viettel-red)";
    }
    toast.textContent = message;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(10px)";
      toast.style.transition = "all 0.25s ease";
      setTimeout(() => toast.remove(), 250);
    }, 3200);
  }

  // Tự động phân loại icon thiết bị dựa vào tên hoặc hãng
  function inferDeviceTypeIcon(device) {
    if (device.device_type) {
      switch (device.device_type) {
        case "router": return { icon: "🌐", label: "Router / Modem" };
        case "camera": return { icon: "📹", label: "Camera IP" };
        case "phone": return { icon: "📱", label: "Điện thoại / Tablet" };
        case "pc": return { icon: "💻", label: "Máy tính / PC" };
        case "tv": return { icon: "📺", label: "Smart TV / Box" };
        case "iot": return { icon: "🔌", label: "Thiết bị Smart Home" };
        case "other": return { icon: "⚙️", label: "Thiết bị khác" };
        default: break;
      }
    }

    const v = (device.vendor || "").toLowerCase();
    const h = (device.hostname || "").toLowerCase();
    const ip = device.ip || "";

    // Gateway / Router
    if (ip.endsWith(".1") || v.includes("zte") || v.includes("huawei") || v.includes("draytek") || v.includes("cisco") || v.includes("tp-link")) {
      if (ip.endsWith(".1")) return { icon: "🌐", label: "Router Gateway Viettel" };
    }

    // Camera
    if (v.includes("hikvision") || v.includes("ezviz") || v.includes("dahua") || v.includes("imou") || h.includes("cam")) {
      return { icon: "📹", label: "Camera IP" };
    }

    // Điện thoại / Máy tính bảng
    if (v.includes("samsung") || v.includes("apple") || v.includes("motorola") || v.includes("xiaomi") || v.includes("oppo") || v.includes("vivo") || h.includes("iphone") || h.includes("galaxy")) {
      return { icon: "📱", label: "Điện thoại / Tablet" };
    }

    // Máy tính PC / Laptop
    if (v.includes("realtek") || v.includes("intel") || v.includes("dell") || v.includes("hp") || v.includes("lenovo") || v.includes("wistron") || v.includes("asus") || v.includes("gigabyte") || v.includes("msi") || h.includes("pc") || h.includes("laptop")) {
      return { icon: "💻", label: "Máy tính" };
    }

    // Smart TV
    if (v.includes("sony") || v.includes("lg") || h.includes("tv") || h.includes("box")) {
      return { icon: "📺", label: "Smart TV" };
    }

    // IoT
    if (v.includes("dragon") || v.includes("tuya") || v.includes("espressif") || v.includes("sonoff")) {
      return { icon: "🔌", label: "Thiết bị IoT" };
    }

    return { icon: "⚙️", label: "Thiết bị mạng" };
  }

  // Hiển thị badge nhận diện hệ điều hành (OS Badge Formatter)
  function renderOsBadge(osName) {
    if (!osName || osName === "Unknown" || osName === "Chưa xác định") {
      return `<span class="os-badge os-unknown" title="Chưa nhận diện được OS">Chưa rõ</span>`;
    }
    const lower = osName.toLowerCase();
    let icon = "💻";
    let cls = "os-unknown";
    if (lower.includes("windows")) { icon = "🪟"; cls = "os-windows"; }
    else if (lower.includes("linux")) { icon = "🐧"; cls = "os-linux"; }
    else if (lower.includes("apple") || lower.includes("ios") || lower.includes("macos")) { icon = "🍏"; cls = "os-apple"; }
    else if (lower.includes("android")) { icon = "🤖"; cls = "os-android"; }
    else if (lower.includes("router") || lower.includes("mikrotik") || lower.includes("zte")) { icon = "🌐"; cls = "os-router"; }
    else if (lower.includes("iot")) { icon = "🔌"; cls = "os-iot"; }
    return `<span class="os-badge ${cls}" title="${escapeHtml(osName)}">${icon} ${escapeHtml(osName)}</span>`;
  }

  // -------------------------------------------------------------------------
  // Đồng hồ thời gian thực
  // -------------------------------------------------------------------------

  function tickClock() {
    if (el.systemClock) {
      el.systemClock.textContent = new Date().toLocaleTimeString("vi-VN", { hour12: false });
    }
  }
  setInterval(tickClock, 1000);
  tickClock();

  // -------------------------------------------------------------------------
  // Chuyển Tab Giao Diện (Router Tabs: Devices, Traffic, Events)
  // -------------------------------------------------------------------------

  function switchTab(targetTab) {
    el.tabNavItems.forEach(t => {
      t.classList.toggle("active", t.dataset.tab === targetTab);
    });

    if (el.tabDevices) el.tabDevices.style.display = targetTab === "devices" ? "block" : "none";
    if (el.tabTraffic) el.tabTraffic.style.display = targetTab === "traffic" ? "block" : "none";
    if (el.tabConnections) el.tabConnections.style.display = targetTab === "connections" ? "block" : "none";
    if (el.tabSecurity) el.tabSecurity.style.display = targetTab === "security" ? "block" : "none";
    if (el.tabLab) el.tabLab.style.display = targetTab === "lab" ? "block" : "none";
    if (el.tabEvents) el.tabEvents.style.display = targetTab === "events" ? "block" : "none";

    if (targetTab === "traffic") {
      setTimeout(drawTrafficChart, 50);
    }
    if (targetTab === "lab") {
      loadLabs();
    }
  }

  el.tabNavItems.forEach(tab => {
    tab.addEventListener("click", (e) => {
      e.preventDefault();
      const targetTab = tab.dataset.tab;
      if (targetTab) {
        window.location.hash = targetTab;
        switchTab(targetTab);
      }
    });
  });

  // Tự động mở tab theo hash URL
  window.addEventListener("hashchange", () => {
    const hash = (window.location.hash || "").replace("#", "");
    if (["devices", "traffic", "connections", "security", "lab", "events"].includes(hash)) {
      switchTab(hash);
    }
  });

  if (window.location.hash) {
    const initialTab = window.location.hash.replace("#", "");
    if (["devices", "traffic", "connections", "security", "lab", "events"].includes(initialTab)) {
      switchTab(initialTab);
    }
  }

  // -------------------------------------------------------------------------
  // Render: 4 Khối tóm tắt thông số hệ thống
  // -------------------------------------------------------------------------

  function renderOverviewCards() {
    const net = state.network || {};
    const stats = state.stats || {};

    // 1. Internet Status
    const isOnline = net.internet_status === "online";
    if (el.topInternetStatus) {
      if (isOnline) {
        el.topInternetStatus.className = "status-val online";
        el.topInternetStatus.textContent = "● Đang kết nối";
      } else {
        el.topInternetStatus.className = "status-val offline";
        el.topInternetStatus.textContent = "● Mất kết nối";
      }
    }

    if (el.cardInternetVal) {
      el.cardInternetVal.textContent = isOnline ? "Hoạt động bình thường" : "Mất kết nối Internet";
      el.cardInternetVal.className = `card-main-val ${isOnline ? "text-green" : "text-red"}`;
    }
    if (el.cardInternetSub) {
      el.cardInternetSub.textContent = `Độ trễ: ${net.internet_latency_ms != null ? net.internet_latency_ms + " ms" : "--"}`;
    }

    // 2. Gateway & Subnet
    if (el.cardGatewayVal) el.cardGatewayVal.textContent = getDisplayIp(net.gateway || "--");
    if (el.cardSubnetSub) el.cardSubnetSub.textContent = `Subnet: ${getDisplayIp(net.subnet || "--")}`;
    if (el.gatewayModelText) {
      if (net.subnet) {
        el.gatewayModelText.innerHTML = `Modem GPON Gateway &bull; Dải mạng LAN ${escapeHtml(getDisplayIp(net.subnet))}`;
      } else {
        el.gatewayModelText.innerHTML = `Modem GPON Gateway &bull; Dải mạng LAN ***.***.***.*** /24`;
      }
    }
    if (el.scanRangeInput && !el.scanRangeInput.dataset.userEdited) {
      if (state.isIpMasked) {
        el.scanRangeInput.value = "";
        el.scanRangeInput.placeholder = "🔒 Dải IP đang ẩn bảo mật (Nhấp 'Hiện IP' để xem)";
      } else if (net.subnet) {
        el.scanRangeInput.value = net.subnet;
        el.scanRangeInput.placeholder = net.subnet;
      }
    }

    // 3. Devices count
    const total = state.devices.length;
    const online = state.devices.filter(d => d.status === "online").length;
    if (el.cardDevicesVal) el.cardDevicesVal.textContent = `${online} / ${total} Online`;
    if (el.cardDevicesSub) {
      el.cardDevicesSub.textContent = `Độ trễ TB: ${stats.avg_latency_ms != null ? stats.avg_latency_ms + " ms" : "--"}`;
    }

    // Quick counts in nav
    if (el.quickOnlineCount) el.quickOnlineCount.textContent = online;
    if (el.quickTotalCount) el.quickTotalCount.textContent = total;

    // 4. Host Bandwidth
    const lastSample = state.trafficHistory[state.trafficHistory.length - 1];
    if (lastSample && el.cardTrafficVal) {
      el.cardTrafficVal.textContent = `↓ ${formatBytes(lastSample.download_speed)}  ↑ ${formatBytes(lastSample.upload_speed)}`;
    }
    if (el.cardTrafficIface) {
      el.cardTrafficIface.textContent = `Card: ${net.interface || "Ethernet"}`;
    }

    // Host Info Widget Specs (Tab 2)
    if (el.hostHostname) el.hostHostname.textContent = getDisplayHostname(net.hostname || "--");
    if (el.hostIp) el.hostIp.textContent = getDisplayIp(net.local_ip || "--");
    if (el.hostGw) el.hostGw.textContent = getDisplayIp(net.gateway || "--");
    if (el.hostSubnet) el.hostSubnet.textContent = getDisplayIp(net.subnet || "--");
    if (el.hostMac) el.hostMac.innerHTML = formatMac(net.mac || "--");
    if (el.hostUptime) el.hostUptime.textContent = formatUptime(stats.uptime_seconds);

    // Filter pill count badges
    if (el.countAll) el.countAll.textContent = total;
    if (el.countOnline) el.countOnline.textContent = online;
    if (el.countOffline) el.countOffline.textContent = total - online;

    // Render Wi-Fi / Ethernet adapter & ISP Opt-in
    renderAdapterInfo();
    renderIspInfo();
  }

  // -------------------------------------------------------------------------
  // Render: Bảng danh sách thiết bị LAN (Chuẩn bảng Viettel Router)
  // -------------------------------------------------------------------------

  function getFilteredDevices() {
    let list = state.devices;

    // Lọc theo trạng thái online / offline
    if (state.filter === "online") {
      list = list.filter(d => d.status === "online");
    } else if (state.filter === "offline") {
      list = list.filter(d => d.status === "offline");
    }

    // Lọc theo từ khóa tìm kiếm
    const q = state.searchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter(d => {
        return (
          (d.ip && d.ip.toLowerCase().includes(q)) ||
          (d.mac && d.mac.toLowerCase().includes(q)) ||
          (d.custom_name && d.custom_name.toLowerCase().includes(q)) ||
          (d.hostname && d.hostname.toLowerCase().includes(q)) ||
          (d.vendor && d.vendor.toLowerCase().includes(q))
        );
      });
    }

    return list;
  }

  function renderDeviceTable() {
    if (!el.devicesTbody) return;

    const devices = getFilteredDevices();

    if (devices.length === 0) {
      const msg = state.searchQuery
        ? `Không tìm thấy thiết bị nào khớp với từ khóa "<strong>${escapeHtml(state.searchQuery)}</strong>"`
        : "Không có thiết bị nào trong danh mục này.";
      el.devicesTbody.innerHTML = `
        <tr class="empty-state-row">
          <td colspan="11" style="text-align: center; padding: 36px 12px; color: var(--text-muted);">
            ${msg}
          </td>
        </tr>
      `;
      return;
    }

    const html = devices.map((d, index) => {
      const isOnline = d.status === "online";
      const { icon, label } = inferDeviceTypeIcon(d);
      let displayName = d.custom_name || d.hostname || label;
      let subName = d.custom_name ? (d.hostname || d.vendor) : (d.hostname ? d.vendor : "");
      if (state.isIpMasked && !d.custom_name) {
        displayName = label;
        subName = d.vendor || "";
      }

      // Màu sắc theo độ trễ ping
      let latencyClass = "latency-fast";
      if (d.latency_ms > 50) latencyClass = "latency-slow";
      else if (d.latency_ms > 20) latencyClass = "latency-normal";

      const latencyStr = d.latency_ms != null ? `${d.latency_ms} ms` : "--";

      // Cổng dịch vụ mở (Từng tag rõ ràng, không dính liền số)
      let portsHtml = '<span style="color: var(--text-muted); font-size: 11px;">--</span>';
      if (Array.isArray(d.open_ports) && d.open_ports.length > 0) {
        portsHtml = `<div class="ports-badge-container">${d.open_ports.map(p => `<span class="port-tag" title="Cổng dịch vụ ${p}">${p}</span>`).join(" ")}</div>`;
      }

      return `
        <tr data-mac="${escapeHtml(d.mac)}">
          <td class="cell-index">${index + 1}</td>

          <td>
            <span class="status-pill ${isOnline ? "online" : "offline"}">
              <span class="dot"></span>
              ${isOnline ? "Online" : "Offline"}
            </span>
          </td>

          <td>
            <div class="device-name-container">
              <div class="device-type-icon" title="${label}">${icon}</div>
              <div class="device-title-box">
                <span class="primary-name">${escapeHtml(displayName)}</span>
                ${subName ? `<span class="sub-name">${escapeHtml(subName)}</span>` : ""}
              </div>
            </div>
          </td>

          <td class="cell-ip">${formatIp(d.ip)}</td>

          <td class="cell-mac">${formatMac(d.mac)}</td>

          <td class="cell-vendor" title="${escapeHtml(d.vendor || "")}">
            ${escapeHtml(d.vendor || "Chưa rõ")}
          </td>

          <td class="cell-os">
            ${renderOsBadge(d.os_name)}
          </td>

          <td>${portsHtml}</td>

          <td class="cell-latency ${latencyClass}">${latencyStr}</td>

          <td class="cell-time">${formatTimeAgo(d.last_seen)}</td>

          <td style="text-align: center;">
            <button type="button" class="btn-action-edit" data-mac="${escapeHtml(d.mac)}" title="Đổi tên / Gán nhãn thiết bị">
              ✏️ Sửa
            </button>
          </td>
        </tr>
      `;
    }).join("");

    el.devicesTbody.innerHTML = html;
  }

  // -------------------------------------------------------------------------
  // Render: Biểu đồ băng thông Chart.js
  // -------------------------------------------------------------------------

  let trafficChartInstance = null;

  function drawTrafficChart() {
    const canvas = el.trafficCanvas;
    if (!canvas) return;

    const history = state.trafficHistory.slice(-40);
    const labels = history.map(p => {
        const d = new Date(p.timestamp);
        return d.toLocaleTimeString("vi-VN", { minute: '2-digit', second: '2-digit' });
    });
    const downValues = history.map(p => (p.download_speed || 0) / 1024); // KB/s
    const upValues = history.map(p => (p.upload_speed || 0) / 1024); // KB/s

    if (trafficChartInstance) {
        trafficChartInstance.data.labels = labels;
        trafficChartInstance.data.datasets[0].data = downValues;
        trafficChartInstance.data.datasets[1].data = upValues;
        trafficChartInstance.update('none'); // Update without animation for realtime feel
    } else {
        if (!window.Chart) return; // Chờ thư viện load
        const ctx = canvas.getContext('2d');
        
        trafficChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Tải về (KB/s)',
                        data: downValues,
                        borderColor: '#0284C7',
                        backgroundColor: 'rgba(2, 132, 199, 0.2)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4, // Tạo đường cong mượt mà
                        pointRadius: 0,
                        pointHoverRadius: 4
                    },
                    {
                        label: 'Tải lên (KB/s)',
                        data: upValues,
                        borderColor: '#F59E0B',
                        backgroundColor: 'rgba(245, 158, 11, 0.2)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 0 // Tắt animation ban đầu để tránh giật lag khi realtime
                },
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        display: false // Đã có legend HTML tùy chỉnh phía trên
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                if (context.parsed.y !== null) {
                                    label += context.parsed.y.toFixed(1) + ' KB/s';
                                }
                                return label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        grid: {
                            display: false
                        },
                        ticks: {
                            maxTicksLimit: 6
                        }
                    },
                    y: {
                        display: true,
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    }
                }
            }
        });
    }
  }


  window.addEventListener("resize", drawTrafficChart);

  // -------------------------------------------------------------------------
  // Render: Nhật ký sự kiện hệ thống
  // -------------------------------------------------------------------------

  function renderEvents() {
    if (!el.eventFeed) return;

    if (!state.events || state.events.length === 0) {
      el.eventFeed.innerHTML = `<li class="event-none">Chưa có sự kiện nào được ghi nhận.</li>`;
      return;
    }

    const items = state.events.slice(0, 40).map(ev => {
      return `
        <li>
          <span class="event-msg">${escapeHtml(ev.message)}</span>
          <span class="event-time">${formatTimeAgo(ev.created_at)}</span>
        </li>
      `;
    });

    el.eventFeed.innerHTML = items.join("");
  }

  // -------------------------------------------------------------------------
  // Render: Connections & Packets (Tab 4)
  // -------------------------------------------------------------------------
  function renderConnections() {
    if (!el.connectionsTbody) return;
    if (state.connections.length === 0) {
      el.connectionsTbody.innerHTML = '<tr class="empty-state-row"><td colspan="6">Chưa có kết nối nào.</td></tr>';
      return;
    }
    const html = state.connections.map(c => {
      let suspCls = c.is_suspicious ? "status-suspicious" : "";
      const svc = c.service_name || "--";
      return `<tr>
        <td class="${suspCls}">${formatIp(c.src_ip)}:${c.src_port}</td>
        <td class="${suspCls}">${formatIp(c.dst_ip)}:${c.dst_port}</td>
        <td><span class="badge-protocol ${c.protocol.toLowerCase()}">${escapeHtml(c.protocol)}</span></td>
        <td><span class="badge-service">${escapeHtml(svc)}</span></td>
        <td class="${suspCls}">${escapeHtml(c.status || "UNKNOWN")}</td>
        <td>${escapeHtml(c.process_name || "--")} (PID: ${c.pid || "--"})</td>
      </tr>`;
    }).join("");
    el.connectionsTbody.innerHTML = html;
  }

  function renderPackets() {
    if (!el.packetsTbody) return;
    if (state.packets.length === 0) {
      el.packetsTbody.innerHTML = '<tr class="empty-state-row"><td colspan="4">Chưa có gói tin nào.</td></tr>';
      return;
    }
    const html = state.packets.map(p => {
      return `<tr>
        <td>${formatTimeAgo(p.timestamp)}</td>
        <td><span class="badge-protocol ${p.protocol.toLowerCase()}">${escapeHtml(p.protocol)}</span></td>
        <td>${p.packet_size} bytes</td>
        <td style="${p.is_anomaly ? 'color:#EE0033;font-weight:bold;' : ''}">${escapeHtml(p.info)} ${p.tcp_flags ? '['+p.tcp_flags+']' : ''}</td>
      </tr>`;
    }).join("");
    el.packetsTbody.innerHTML = html;
  }

  // -------------------------------------------------------------------------
  // Render: Security SOC (Tab 5)
  // -------------------------------------------------------------------------
  function renderSecurityEvents() {
    if (!el.securityTbody) return;

    let infoCount = 0;
    let warnCount = 0;
    let critCount = 0;
    
    state.securityEvents.forEach(e => {
      if (e.severity === 1) infoCount++;
      else if (e.severity === 2) warnCount++;
      else if (e.severity >= 3) critCount++;
    });

    if (el.threatInfoCount) el.threatInfoCount.textContent = infoCount;
    if (el.threatWarnCount) el.threatWarnCount.textContent = warnCount;
    if (el.threatCritCount) el.threatCritCount.textContent = critCount;

    if (state.securityEvents.length === 0) {
      el.securityTbody.innerHTML = '<tr class="empty-state-row"><td colspan="5">Tuyệt vời! Không phát hiện mối đe dọa an ninh nào.</td></tr>';
      return;
    }

    const html = state.securityEvents.map(e => {
      let levelText = "Info";
      let rowClass = "threat-row-info";
      
      if (e.severity === 2) {
        levelText = "Warning";
        rowClass = "threat-row-warning";
      } else if (e.severity >= 3) {
        levelText = "Critical";
        rowClass = "threat-row-critical";
      }

      return `<tr class="${rowClass}">
        <td>${formatTimeAgo(e.created_at)}</td>
        <td><span style="font-weight:bold;">${levelText}</span></td>
        <td style="font-weight:bold;">${escapeHtml(e.threat_category)}</td>
        <td>${formatIp(e.src_ip || "--")}</td>
        <td>${escapeHtml(e.details)}</td>
      </tr>`;
    }).join("");
    el.securityTbody.innerHTML = html;
  }

  // -------------------------------------------------------------------------
  // Xử lý Sự kiện người dùng (Interactions)
  // -------------------------------------------------------------------------

  // Nhập từ khóa tìm kiếm
  if (el.searchInput) {
    el.searchInput.addEventListener("input", (e) => {
      state.searchQuery = e.target.value;
      if (el.clearSearch) {
        el.clearSearch.style.display = state.searchQuery ? "block" : "none";
      }
      renderDeviceTable();
    });
  }

  if (el.clearSearch) {
    el.clearSearch.addEventListener("click", () => {
      if (el.searchInput) el.searchInput.value = "";
      state.searchQuery = "";
      el.clearSearch.style.display = "none";
      renderDeviceTable();
      if (el.searchInput) el.searchInput.focus();
    });
  }

  // Bộ lọc Tab (Tất cả, Đang Online, Đã Offline)
  el.filterPills.forEach(btn => {
    btn.addEventListener("click", () => {
      el.filterPills.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.filter = btn.dataset.filter || "all";
      renderDeviceTable();
    });
  });

  // Khi người dùng chỉnh sửa dải IP quét thủ công
  if (el.scanRangeInput) {
    el.scanRangeInput.addEventListener("input", () => {
      el.scanRangeInput.dataset.userEdited = "true";
    });
  }

  // Nút quét mạng LAN
  if (el.btnScan) {
    el.btnScan.addEventListener("click", async () => {
      const rangeVal = (el.scanRangeInput ? el.scanRangeInput.value.trim() : "") || "192.168.1.0/24";
      el.btnScan.classList.add("scanning");
      el.btnScan.disabled = true;
      if (el.scanLabel) el.scanLabel.textContent = `Đang quét ${rangeVal}...`;

      try {
        await fetch(`${API_BASE}/api/devices/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ range: rangeVal }),
        });
        showToast(`Đã bắt đầu quét dải IP: ${rangeVal}`, "info");
      } catch (e) {
        console.error("Lỗi khi yêu cầu quét:", e);
        showToast("Không thể kích hoạt quét mạng. Kiểm tra lại kết nối!", "error");
      } finally {
        setTimeout(() => {
          el.btnScan.classList.remove("scanning");
          el.btnScan.disabled = false;
          if (el.scanLabel) el.scanLabel.textContent = "Quét mạng ngay";
        }, 3500);
      }
    });
  }

  // Mở modal sửa tên thiết bị khi click nút ✏️
  if (el.devicesTbody) {
    el.devicesTbody.addEventListener("click", (e) => {
      const editBtn = e.target.closest(".btn-action-edit");
      if (!editBtn) return;

      const mac = editBtn.dataset.mac;
      const device = state.devices.find(d => d.mac === mac);
      if (!device) return;

      state.editingMac = mac;
      state.editingType = device.device_type || "other";

      if (el.modalDeviceIp) el.modalDeviceIp.textContent = getDisplayIp(device.ip || "--");
      if (el.modalDeviceMac) el.modalDeviceMac.textContent = device.mac;
      if (el.inputCustomName) el.inputCustomName.value = device.custom_name || "";

      // Đánh dấu nút chọn loại thiết bị đang chọn
      if (el.typeSelector) {
        Array.from(el.typeSelector.querySelectorAll(".type-btn")).forEach(btn => {
          btn.classList.toggle("active", btn.dataset.type === state.editingType);
        });
      }

      if (el.editModal) {
        el.editModal.style.display = "flex";
      }
      if (el.inputCustomName) {
        el.inputCustomName.focus();
      }
    });
  }

  // Chọn loại thiết bị trong Modal
  if (el.typeSelector) {
    el.typeSelector.addEventListener("click", (e) => {
      const opt = e.target.closest(".type-btn");
      if (!opt) return;
      Array.from(el.typeSelector.querySelectorAll(".type-btn")).forEach(b => b.classList.remove("active"));
      opt.classList.add("active");
      state.editingType = opt.dataset.type || "other";
    });
  }

  // Đóng modal
  function closeModal() {
    if (el.editModal) el.editModal.style.display = "none";
    state.editingMac = null;
  }

  if (el.modalClose) el.modalClose.addEventListener("click", closeModal);
  if (el.modalCancel) el.modalCancel.addEventListener("click", closeModal);
  if (el.editModal) {
    el.editModal.addEventListener("click", (e) => {
      if (e.target === el.editModal) closeModal();
    });
  }

  // Lưu chỉnh sửa thiết bị
  if (el.editForm) {
    el.editForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!state.editingMac) return;

      const customName = el.inputCustomName ? el.inputCustomName.value.trim() : "";
      const deviceType = state.editingType;

      try {
        const res = await fetch(`${API_BASE}/api/devices/${state.editingMac}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            custom_name: customName,
            device_type: deviceType,
          }),
        });

        if (res.ok) {
          showToast("Đã lưu thông tin thiết bị thành công!", "success");
          const dev = state.devices.find(d => d.mac === state.editingMac);
          if (dev) {
            dev.custom_name = customName;
            dev.device_type = deviceType;
            renderDeviceTable();
          }
          closeModal();
        } else {
          showToast("Lỗi khi lưu cấu hình thiết bị!", "error");
        }
      } catch (err) {
        console.error("Lỗi khi lưu thiết bị:", err);
        showToast("Lỗi kết nối tới máy chủ!", "error");
      }
    });
  }

  // -------------------------------------------------------------------------
  // ẨN / HIỆN ĐỊA CHỈ IP MẠNG (PRIVACY IP MASKING CONTROLLER)
  // -------------------------------------------------------------------------

  if (el.btnToggleIpMask) {
    el.btnToggleIpMask.addEventListener("click", () => {
      state.isIpMasked = !state.isIpMasked;

      if (state.isIpMasked) {
        el.btnToggleIpMask.classList.add("is-masked");
        if (el.ipMaskIcon) el.ipMaskIcon.textContent = "🔒";
        if (el.ipMaskLabel) el.ipMaskLabel.textContent = "Hiện IP mạng";
        showToast("Đã ẩn toàn bộ địa chỉ IP mạng nội bộ (Privacy Mode ON)", "info");
      } else {
        el.btnToggleIpMask.classList.remove("is-masked");
        if (el.ipMaskIcon) el.ipMaskIcon.textContent = "👁️";
        if (el.ipMaskLabel) el.ipMaskLabel.textContent = "Ẩn IP mạng";
        showToast("Đã hiển thị lại đầy đủ địa chỉ IP mạng", "info");
      }

      // Cập nhật lại toàn bộ giao diện
      renderOverviewCards();
      renderDeviceTable();
      renderConnections();
      renderSecurityEvents();
    });
  }

  // -------------------------------------------------------------------------
  // PHÒNG VỆ CHỐNG CHỤP MÀN HÌNH (ANTI-SCREENSHOT RED SHIELD DEFENSE)
  // -------------------------------------------------------------------------

  function triggerScreenshotProtection(reason = "Phát hiện thao tác chụp màn hình (PrtScn / Snipping Tool)") {
    if (state.isShieldActive) return;
    state.isShieldActive = true;

    // Ghi nhận thời gian và lý do kích hoạt
    const nowStr = new Date().toLocaleTimeString("vi-VN", { hour12: false });
    if (el.shieldDetectedTime) el.shieldDetectedTime.textContent = nowStr;
    if (el.shieldDetectedReason) el.shieldDetectedReason.textContent = reason;

    // Bật khiên toàn màn hình với nền đỏ cảnh báo và làm mờ hoàn toàn giao diện nền
    document.body.classList.add("shield-mode-active");
    if (el.securityScreenshotShield) {
      el.securityScreenshotShield.style.display = "flex";
      el.securityScreenshotShield.classList.add("active");
    }

    // Ghi lại sự kiện an ninh vào bộ nhớ RAM SOC
    const securityEvent = {
      created_at: new Date().toISOString(),
      severity: 3,
      threat_category: "Screen Capture Blocked",
      src_ip: "Local Console",
      details: `Kích hoạt khiên cảnh báo đỏ chống chụp màn hình. Lý do: ${reason}. Đã cô lập và che phủ toàn bộ dữ liệu mạng.`
    };
    state.securityEvents.unshift(securityEvent);
    if (state.securityEvents.length > 100) state.securityEvents.pop();
    renderSecurityEvents();

    // Làm sạch clipboard để nếu người dùng chụp qua clipboard thì không thu được dữ liệu
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText("[CẢNH BÁO AN NINH MẠNG] Hành vi chụp màn hình hoặc sao chép thông tin mạng đã bị chặn bởi NETWORK MANAGER - Hệ Thống Quản Trị Mạng LAN.");
      }
    } catch (e) {
      // Bỏ qua nếu trình duyệt không cấp quyền truy cập clipboard
    }

    // Đếm ngược 3 giây trước khi người dùng được phép mở khóa
    state.shieldSecondsLeft = 3;
    if (el.btnUnlockShield) {
      el.btnUnlockShield.disabled = true;
      el.btnUnlockShield.style.opacity = "0.7";
      el.btnUnlockShield.style.cursor = "not-allowed";
      el.btnUnlockShield.innerHTML = `🛡️ Tôi Đã Hiểu &bull; Mở Khóa Màn Hình (<span id="shield-countdown">${state.shieldSecondsLeft}</span>s)`;
      el.shieldCountdown = document.getElementById("shield-countdown");
    }

    clearInterval(state.shieldCountdownTimer);
    state.shieldCountdownTimer = setInterval(() => {
      state.shieldSecondsLeft--;
      if (state.shieldSecondsLeft <= 0) {
        clearInterval(state.shieldCountdownTimer);
        state.shieldCountdownTimer = null;
        if (el.btnUnlockShield) {
          el.btnUnlockShield.disabled = false;
          el.btnUnlockShield.style.opacity = "1";
          el.btnUnlockShield.style.cursor = "pointer";
          el.btnUnlockShield.innerHTML = "🛡️ Tôi Đã Hiểu &bull; Mở Khóa Màn Hình (Sẵn sàng)";
        }
      } else {
        if (el.shieldCountdown) el.shieldCountdown.textContent = state.shieldSecondsLeft;
      }
    }, 1000);
  }

  function unlockScreenshotProtection() {
    state.isShieldActive = false;
    clearInterval(state.shieldCountdownTimer);
    state.shieldCountdownTimer = null;

    document.body.classList.remove("shield-mode-active");
    if (el.securityScreenshotShield) {
      el.securityScreenshotShield.style.display = "none";
      el.securityScreenshotShield.classList.remove("active");
    }

    showToast("Đã mở khóa màn hình quản trị mạng an toàn.", "success");
  }

  // Nút mở khóa khiên
  if (el.btnUnlockShield) {
    el.btnUnlockShield.addEventListener("click", () => {
      if (state.shieldSecondsLeft <= 0) {
        unlockScreenshotProtection();
      }
    });
  }

  // Nút thử nghiệm khiên
  if (el.btnTestShield) {
    el.btnTestShield.addEventListener("click", () => {
      triggerScreenshotProtection("Thử nghiệm kiểm tra khiên đỏ cảnh báo chống chụp màn hình (Security Test)");
    });
  }

  // Bắt phím PrintScreen (PrtScn) & Phím tắt chụp màn hình
  window.addEventListener("keyup", (e) => {
    if (e.key === "PrintScreen" || e.keyCode === 44) {
      triggerScreenshotProtection("Phát hiện phím PrintScreen (PrtScn) / Snipping Tool");
    }
  });

  window.addEventListener("keydown", (e) => {
    // PrintScreen
    if (e.key === "PrintScreen" || e.keyCode === 44) {
      triggerScreenshotProtection("Phát hiện phím PrintScreen (PrtScn)");
      return;
    }

    // Windows Snipping Tool: Win + Shift + S hoặc Ctrl + Shift + S
    if (e.shiftKey && (e.key === "S" || e.key === "s") && (e.metaKey || e.ctrlKey)) {
      triggerScreenshotProtection("Phát hiện tổ hợp phím Snipping Tool (Win/Ctrl + Shift + S)");
      return;
    }

    // Mac screenshot: Cmd + Shift + 3, Cmd + Shift + 4, Cmd + Shift + 5
    if (e.metaKey && e.shiftKey && ["3", "4", "5"].includes(e.key)) {
      triggerScreenshotProtection("Phát hiện phím tắt chụp màn hình MacOS (Cmd + Shift + 3/4/5)");
      return;
    }

    // Ngăn phím Ctrl + P (In ấn / In ra PDF)
    if ((e.ctrlKey || e.metaKey) && (e.key === "p" || e.key === "P")) {
      e.preventDefault();
      triggerScreenshotProtection("Phát hiện phím tắt In ấn / Xuất PDF (Ctrl + P)");
      return;
    }
  });

  // Chống in ấn / Xuất PDF
  window.addEventListener("beforeprint", () => {
    triggerScreenshotProtection("Phát hiện thao tác In ấn hoặc Xuất tệp PDF (Print Preview)");
  });

  // -------------------------------------------------------------------------
  // PHÒNG VỆ CHÍNH CHỐNG SNIPPING TOOL / SCREEN RECORDER (FOCUS-LOSS DEFENSE)
  // -----------------------------------------------------------------------
  // Giới hạn nền tảng phải biết rõ:
  //  - Phím Win (Win + Shift + S) KHÔNG BAO GIỜ tới được trang web vì Hệ điều hành chặn.
  //  - Bấm PrtScn: HĐH chụp vào clipboard TRƯỚC khi trang web nhận sự kiện phím.
  // => Cơ chế duy nhất hoạt động THỰC TẾ trên trình duyệt: phát hiện cửa sổ MẤT TIÊU ĐIỂM.
  // Khi Snipping Tool mở (Win+Shift+S), màn hình mờ đi và trang web mất focus ngay lập tức.
  // Trang phản ứng bằng cách phủ KHIÊN ĐỎ TRƯỚC khi người dùng kịp kéo vùng chọn,
  // nên mọi ảnh chụp về sau chỉ thu được nền cảnh báo đỏ.
  let blurTriggerTimer = null;
  window.addEventListener("blur", () => {
    clearTimeout(blurTriggerTimer);
    // Chờ một nhịp ngắn để bỏ qua trường hợp click ra ngoài rồi quay lại ngay lập tức
    blurTriggerTimer = setTimeout(() => {
      if (document.hasFocus()) return; // Đã lấy lại focus -> không phải chụp màn hình
      if (!state.isShieldActive) {
        triggerScreenshotProtection("Phát hiện cửa sổ mất tiêu điểm (Snipping Tool Win+Shift+S / Screen Recorder / Chuyển ứng dụng)");
      }
    }, 120);
  });
  window.addEventListener("focus", () => {
    clearTimeout(blurTriggerTimer);
    // Khi quay lại cửa sổ mà khiên đang bật (do mất tiêu điểm trước đó),
    // giữ nguyên khiên - người dùng phải chờ hết đếm ngược rồi bấm "Mở Khóa Màn Hình".
  });

  // -------------------------------------------------------------------------
  // WebSocket kết nối thời gian thực (Realtime Synchronizer)
  // -------------------------------------------------------------------------

  let socket = null;
  let reconnectTimer = null;

  function connectWs() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "localhost:8000";
    const url = `${protocol}//${host}/ws/dashboard`;

    if (el.topWsStatus) {
      el.topWsStatus.className = "status-val offline";
      el.topWsStatus.textContent = "● Đang kết nối...";
    }

    try {
      socket = new WebSocket(url);
    } catch (e) {
      console.warn("WebSocket init error:", e);
      scheduleReconnect();
      return;
    }

    socket.addEventListener("open", () => {
      if (el.topWsStatus) {
        el.topWsStatus.className = "status-val realtime";
        el.topWsStatus.textContent = "● Thời gian thực";
      }
    });

    socket.addEventListener("message", (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleWsMessage(msg);
      } catch (err) {
        // bỏ qua tin nhắn định dạng sai
      }
    });

    socket.addEventListener("close", () => {
      if (el.topWsStatus) {
        el.topWsStatus.className = "status-val offline";
        el.topWsStatus.textContent = "● Mất kết nối...";
      }
      scheduleReconnect();
    });

    socket.addEventListener("error", () => {
      if (socket) socket.close();
    });
  }

  function scheduleReconnect() {
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connectWs, 3000);
  }

  function handleWsMessage(msg) {
    if (!msg || !msg.type) return;

    switch (msg.type) {
      case "devices_update":
        state.devices = msg.data || [];
        renderOverviewCards();
        renderDeviceTable();
        break;

      case "network_update":
        state.network = { ...state.network, ...(msg.data || {}) };
        renderOverviewCards();
        break;

      case "internet_update":
        state.network = {
          ...state.network,
          internet_status: msg.data.status,
          internet_latency_ms: msg.data.latency_ms,
        };
        renderOverviewCards();
        break;

      case "traffic_update":
        if (msg.data) {
          state.trafficHistory.push(msg.data);
          if (state.trafficHistory.length > 80) state.trafficHistory.shift();
          renderOverviewCards();
          drawTrafficChart();
        }
        break;

      case "traffic_history":
        if (Array.isArray(msg.data)) {
          state.trafficHistory = msg.data;
          drawTrafficChart();
        }
        break;

      case "stats_update":
        state.stats = msg.data || {};
        renderOverviewCards();
        break;

      case "event":
        if (msg.data) {
          if (msg.data.severity !== undefined) {
             // Đây là security event
             state.securityEvents.unshift(msg.data);
             if (state.securityEvents.length > 100) state.securityEvents.pop();
             renderSecurityEvents();
          } else {
             state.events.unshift(msg.data);
             if (state.events.length > 50) state.events.pop();
             renderEvents();
          }
        }
        break;

      case "connections_update":
        if (msg.data) {
          state.connections = msg.data;
          renderConnections();
        }
        break;

      case "packet":
        if (msg.data) {
          // Wrap into packet DB format manually to display
          const p = {
             timestamp: new Date().toISOString(),
             protocol: msg.data.protocol,
             packet_size: msg.data.packet_len,
             info: msg.data.info,
             tcp_flags: msg.data.tcp_flags,
             is_anomaly: msg.data.has_threat ? 1 : 0
          };
          state.packets.unshift(p);
          if (state.packets.length > 100) state.packets.pop();
          renderPackets();
        }
        break;

      default:
        break;
    }
  }

  // -------------------------------------------------------------------------
  // Thông tin Card mạng Wi-Fi / Ethernet (Adapter Specs)
  // -------------------------------------------------------------------------

  async function loadAdapterInfo() {
    try {
      const res = await fetch(`${API_BASE}/api/network/adapter`);
      if (res.ok) {
        state.adapterInfo = await res.json();
        renderAdapterInfo();
      }
    } catch (e) {
      console.warn("Không thể tải thông số card mạng:", e);
    }
  }

  function renderAdapterInfo() {
    const ad = state.adapterInfo;
    if (!ad) return;

    if (el.adapterBadgeType) {
      el.adapterBadgeType.textContent = ad.interface_type || "Card Mạng";
      el.adapterBadgeType.className = `badge-adapter-type ${ad.interface_type === "Wi-Fi" ? "wifi" : "ethernet"}`;
    }
    if (el.adapterName) {
      el.adapterName.textContent = ad.adapter_name || "--";
    }

    if (ad.interface_type === "Wi-Fi") {
      if (el.wifiRowSsid) el.wifiRowSsid.style.display = "flex";
      if (el.wifiSsid) el.wifiSsid.textContent = ad.ssid || "Chưa kết nối";
      if (el.wifiRowBssid) el.wifiRowBssid.style.display = "flex";
      if (el.wifiBssid) el.wifiBssid.innerHTML = formatMac(ad.bssid || "--");
      if (el.wifiRowSignal) el.wifiRowSignal.style.display = "flex";
      if (el.wifiSignalFill) el.wifiSignalFill.style.width = `${Math.min(100, Math.max(0, ad.signal_quality || 0))}%`;
      if (el.wifiSignalText) el.wifiSignalText.textContent = `${ad.signal_quality != null ? ad.signal_quality : "--"}%`;
      if (el.wifiRowRadio) el.wifiRowRadio.style.display = "flex";
      if (el.wifiRadio) el.wifiRadio.textContent = ad.radio_type || "--";
    } else {
      if (el.wifiRowSsid) el.wifiRowSsid.style.display = "none";
      if (el.wifiRowBssid) el.wifiRowBssid.style.display = "none";
      if (el.wifiRowSignal) el.wifiRowSignal.style.display = "none";
      if (el.wifiRowRadio) el.wifiRowRadio.style.display = "none";
    }

    if (el.adapterSpeed) {
      if (ad.speed_mbps && ad.speed_mbps > 0) {
        el.adapterSpeed.textContent = `${ad.speed_mbps} Mbps`;
      } else if (ad.rx_rate_mbps && ad.tx_rate_mbps) {
        el.adapterSpeed.textContent = `Rx: ${ad.rx_rate_mbps} Mbps / Tx: ${ad.tx_rate_mbps} Mbps`;
      } else {
        el.adapterSpeed.textContent = "--";
      }
    }

    if (el.adapterDuplexMtu) {
      el.adapterDuplexMtu.textContent = `Duplex: ${ad.duplex || "Full"} | MTU: ${ad.mtu || 1500}`;
    }
  }

  // -------------------------------------------------------------------------
  // Tra cứu Nhà Mạng ISP & Public IP (Opt-In Consent)
  // -------------------------------------------------------------------------

  async function performIspLookup() {
    if (el.btnLookupIsp) {
      el.btnLookupIsp.disabled = true;
      el.btnLookupIsp.textContent = "⏳ Đang tra cứu dữ liệu ISP...";
    }
    if (el.btnRefreshIsp) {
      el.btnRefreshIsp.disabled = true;
    }

    try {
      const res = await fetch(`${API_BASE}/api/network/isp-lookup`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        state.ispInfo = data;
        renderIspInfo();
        showToast("Đã cập nhật thông tin nhà cung cấp ISP!", "success");
      } else {
        const err = await res.json();
        showToast(err.detail || "Không thể tra cứu thông tin ISP!", "error");
      }
    } catch (e) {
      console.error("Lỗi tra cứu ISP:", e);
      showToast("Lỗi kết nối khi tra cứu thông tin ISP!", "error");
    } finally {
      if (el.btnLookupIsp) {
        el.btnLookupIsp.disabled = false;
        el.btnLookupIsp.textContent = "🔍 Tra cứu Thông tin ISP & Public IP Ngay";
      }
      if (el.btnRefreshIsp) {
        el.btnRefreshIsp.disabled = false;
      }
    }
  }

  function renderIspInfo() {
    if (!state.ispInfo) {
      if (el.ispConsentBox) el.ispConsentBox.style.display = "block";
      if (el.ispResultsBox) el.ispResultsBox.style.display = "none";
      return;
    }

    if (el.ispConsentBox) el.ispConsentBox.style.display = "none";
    if (el.ispResultsBox) el.ispResultsBox.style.display = "block";

    const isp = state.ispInfo;
    if (el.ispPublicIp) el.ispPublicIp.innerHTML = formatIp(isp.public_ip || "--");
    if (el.ispName) el.ispName.textContent = isp.isp || "--";
    if (el.ispAsn) el.ispAsn.textContent = isp.as || "--";
    if (el.ispLocation) {
      const locParts = [isp.city, isp.region, isp.country].filter(Boolean);
      el.ispLocation.textContent = locParts.length > 0 ? locParts.join(", ") : "--";
    }
    if (el.ispTime) el.ispTime.textContent = formatTimeAgo(isp.lookup_time);
  }

  if (el.btnLookupIsp) {
    el.btnLookupIsp.addEventListener("click", performIspLookup);
  }
  if (el.btnRefreshIsp) {
    el.btnRefreshIsp.addEventListener("click", performIspLookup);
  }

  // -------------------------------------------------------------------------
  // Phòng Thí Nghiệm An Ninh Mạng (Security Lab Mode - Tab 6)
  // -------------------------------------------------------------------------

  async function loadLabs() {
    if (!el.securityLabList) return;
    try {
      const res = await fetch(`${API_BASE}/api/lab`);
      if (res.ok) {
        const data = await res.json();
        state.labs = data.labs || [];
        renderLabs();
      }
    } catch (e) {
      console.error("Lỗi nạp bài thực hành an ninh:", e);
      if (el.securityLabList) {
        el.securityLabList.innerHTML = `<div class="empty-state-row" style="color: #DC2626;">Không thể tải bài lab: ${escapeHtml(e.message)}</div>`;
      }
    }
  }

  function renderLabs() {
    if (!el.securityLabList) return;
    if (!state.labs || state.labs.length === 0) {
      el.securityLabList.innerHTML = '<div class="empty-state-row">Chưa có bài thực hành an ninh nào.</div>';
      return;
    }

    const html = state.labs.map(lab => {
      const sim = lab.simulation || {};
      return `
        <div class="lab-card" id="lab-${escapeHtml(lab.id)}">
          <div class="lab-header">
            <div class="lab-title-row">
              <h3 class="lab-title">${escapeHtml(lab.title)}</h3>
              <div class="lab-badges">
                <span class="badge-lab-tag">${escapeHtml(lab.badge || "Network Lab")}</span>
                <span class="badge-lab-diff">${escapeHtml(lab.difficulty || "Standard")}</span>
              </div>
            </div>
          </div>

          <div class="lab-grid-details">
            <div class="lab-step-box step-vuln">
              <div class="step-badge">1. Lỗ Hổng (Vulnerability)</div>
              <p>${escapeHtml(lab.vulnerability)}</p>
            </div>

            <div class="lab-step-box step-attack">
              <div class="step-badge">2. Phương Thức Tấn Công (Attack Concept)</div>
              <p>${escapeHtml(lab.attack_concept)}</p>
            </div>

            <div class="lab-step-box step-detect">
              <div class="step-badge">3. Cơ Chế Phát Hiện (SOC Detection)</div>
              <p>${escapeHtml(lab.detection)}</p>
            </div>

            <div class="lab-step-box step-mitigate">
              <div class="step-badge">4. Biện Pháp Phòng Ngừa (Mitigation)</div>
              <p>${escapeHtml(lab.mitigation)}</p>
            </div>
          </div>

          <div class="lab-code-section">
            <div class="code-title">🛠️ Triển Khai An Toàn (Secure Implementation):</div>
            <pre class="code-block"><code>${escapeHtml(lab.secure_implementation)}</code></pre>
          </div>

          <div class="lab-action-row">
            <div class="lab-sim-desc">
              ${sim.description ? `<span>💡 <em>${escapeHtml(sim.description)}</em></span>` : ""}
            </div>
            <button type="button" class="btn-lab-simulate" data-lab-id="${escapeHtml(lab.id)}">
              ${escapeHtml(sim.button_label || "▶️ Chạy Mô Phỏng")}
            </button>
          </div>
        </div>
      `;
    }).join("");

    el.securityLabList.innerHTML = html;

    // Gắn sự kiện click mô phỏng
    const simBtns = el.securityLabList.querySelectorAll(".btn-lab-simulate");
    simBtns.forEach(btn => {
      btn.addEventListener("click", async () => {
        const labId = btn.dataset.labId;
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = "⏳ Đang mô phỏng...";

        try {
          const res = await fetch(`${API_BASE}/api/lab/simulate/${labId}`, {
            method: "POST"
          });
          const result = await res.json();
          if (res.ok) {
            showToast(result.message || "Đã kích hoạt mô phỏng an ninh!", "success");
          } else {
            showToast(result.detail || "Không thể thực thi mô phỏng", "error");
          }
        } catch (err) {
          showToast("Lỗi kết nối khi gửi lệnh mô phỏng!", "error");
        } finally {
          setTimeout(() => {
            btn.disabled = false;
            btn.textContent = origText;
          }, 2000);
        }
      });
    });
  }

  // -------------------------------------------------------------------------
  // Tải dữ liệu ban đầu qua REST API
  // -------------------------------------------------------------------------

  async function loadInitialData() {
    try {
      const [devRes, netRes, statsRes, evRes, connRes, pktRes, secRes] = await Promise.all([
        fetch(`${API_BASE}/api/devices`),
        fetch(`${API_BASE}/api/network`),
        fetch(`${API_BASE}/api/stats`),
        fetch(`${API_BASE}/api/events?limit=40`),
        fetch(`${API_BASE}/api/connections?limit=100`),
        fetch(`${API_BASE}/api/packets?limit=100`),
        fetch(`${API_BASE}/api/security/events?limit=100`),
      ]);

      if (devRes.ok) state.devices = await devRes.json();
      if (netRes.ok) {
        state.network = await netRes.json();
        if (Array.isArray(state.network.traffic_history)) {
          state.trafficHistory = state.network.traffic_history;
        }
      }
      if (statsRes.ok) state.stats = await statsRes.json();
      if (evRes.ok) state.events = await evRes.json();
      
      if (connRes.ok) {
         const cr = await connRes.json();
         if(cr.data) state.connections = cr.data;
      }
      if (pktRes.ok) {
         const pr = await pktRes.json();
         if(pr.data) state.packets = pr.data;
      }
      if (secRes.ok) {
         const sr = await secRes.json();
         if(sr.data) state.securityEvents = sr.data;
      }

      renderOverviewCards();
      renderDeviceTable();
      renderEvents();
      drawTrafficChart();
      renderConnections();
      renderPackets();
      renderSecurityEvents();

      // Nạp Adapter Specs & Labs
      loadAdapterInfo();
      loadLabs();
    } catch (e) {
      console.warn("Không thể nạp dữ liệu REST API khởi tạo:", e);
    }
  }

  // Khởi động
  loadInitialData().finally(() => {
    connectWs();
  });

})();
