import re
import requests
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, simpledialog
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from whois.parser import PywhoisError
import whois
import Levenshtein
import tldextract
import ipaddress
import base64
import ssl
import socket
import configparser
import os
import idna
import threading
import webbrowser

# Görüntü işleme için Pillow kütüphanesini içe aktarın
from PIL import Image, ImageTk 

class URLAnalyzerApp:
    def __init__(self, master):
        self.master = master
        master.title("CLICK PROTECTION")
        master.geometry("750x700")
        master.resizable(False, False)

        # Logoyu pencere simgesi olarak ayarla
        try:
            # Logo dosyasının yolu, betiğin çalıştığı dizinde olmalı
            script_dir = os.path.dirname(__file__)
            # Logo dosyasının adını CLICKPROLOGO.png olarak kullanın (Türkçe karakterlerden kaçının)
            logo_path = os.path.join(script_dir, "CLICKPROLOGO.png")

            # Görüntüyü yükle ve ImageTk objesine dönüştür
            # Opsiyonel: Simge çok büyükse yeniden boyutlandırabilirsiniz, örneğin (32, 32)
            icon_image = Image.open(logo_path)
            # icon_image = Image.open(logo_path).resize((32, 32), Image.LANCZOS) # İsteğe bağlı olarak yeniden boyutlandırma
            photo = ImageTk.PhotoImage(icon_image)

            # Pencere simgesini ayarla
            self.master.iconphoto(True, photo) 
        except Exception as e:
            print(f"UYARI: Logo yüklenirken hata oluştu: {e}")
            messagebox.showwarning("Logo Hatası", f"Uygulama logosu yüklenemedi: {e}\n'CLICKPROLOGO.png' dosyasının uygulamanızla aynı dizinde olduğundan emin olun.")

        # Yeni renk düzenlemeleri: Lacivertin koyu tonları ve beyaz metin
        self.primary_bg = "#001F3F"  
        self.dark_blue_bg = "#001529" 
        self.text_color_dark = "white" 
        self.text_color_light = "#333333" 
        self.button_color = "#007BFF" 
        self.button_text_color = "white"
        self.result_box_bg = "#f0f0f0" 
        self.white_color = "white" 
        self.dark_gray_detail = "#555555" 
        self.light_green = "#32CD32" 

        master.config(bg=self.primary_bg) 

        self.config = configparser.ConfigParser()
        self.config_path = self._get_config_path()
        self._load_config()

        self.suspicious_keywords = [k.strip().lower() for k in self.config['AnalysisSettings']['suspicious_keywords'].split(',') if k.strip()]
        self.suspicious_extensions = [e.strip().lower() for e in self.config['AnalysisSettings']['suspicious_extensions'].split(',') if e.strip()]
        self.blacklist_file = self.config['Files']['blacklist_file']
        self.real_domains_file = self.config['Files']['real_domains_file']
        
        # Config dosyasında olmayan ayarların varsayılan değerlerle yüklenmesi sağlanıyor
        self.levenshtein_threshold = int(self.config['AnalysisSettings'].get('levenshtein_threshold', '1'))
        self.path_length_threshold = int(self.config['AnalysisSettings'].get('path_length_threshold', '50'))
        self.encoded_char_threshold = int(self.config['AnalysisSettings'].get('encoded_char_threshold', '5'))
        self.risk_threshold_safe = int(self.config['RiskThresholds'].get('safe', '20'))
        self.risk_threshold_suspicious = int(self.config['RiskThresholds'].get('suspicious', '60'))

        self.vt_api_key = self.config['API_Keys'].get('virustotal_api_key', '')

        self.analysis_running = False 
        self.history = [] 
        self.MAX_HISTORY_SIZE = 10 
        self.last_analyzed_url = "" 

        self._create_widgets()
        self._load_history() 

        self.issue_details = {
            "ip_in_url": {"text": "URL'de doğrudan IP adresi kullanımı, meşru sitelerde nadiren görülür ve genellikle şüpheli amaçlar için kullanılır.", "score": 20},
            "at_symbol": {"text": "URL'de '@' sembolü, kullanıcı adı ve şifre gizleme veya gerçek domaini maskeleme amacıyla kullanılabilir.", "score": 20},
            "multiple_subdomains": {"text": "Çok fazla subdomain, URL'yi karmaşıklaştırarak gerçek alan adını gizlemeye çalışabilir.", "score": 10},
            "suspicious_keywords": {"text": "URL'de 'login', 'free', 'update' gibi şüpheli anahtar kelimeler, oltalama girişimlerinde sıkça görülür.", "score": 10},
            "suspicious_extensions": {"text": "URL'nin tehlikeli dosya uzantılarıyla bitmesi (örn. .exe, .scr), kötü amaçlı yazılım indirme riskini gösterir.", "score": 40},
            "suspicious_parameters": {"text": "URL'deki izleme parametreleri (örn. utm_source), oltalama kampanyalarında izleme veya yönlendirme için kullanılabilir.", "score": 15},
            "long_path": {"text": "URL yolu çok uzun. Bu, zararlı veya karmaşık bir yapıya işaret edebilir.", "score": 10},
            "encoded_path_query": {"text": "URL yolunda veya sorgu parametrelerinde kodlanmış (encoded) karakterler tespit edildi. Bu, gizli kötü amaçlı kod veya veri taşımak için kullanılabilir.", "score": 15},
            "obfuscated_parameters": {"text": "URL sorgu parametreleri şifrelenmiş veya anlaşılması zor karakterler içeriyor. Bu, kötü amaçlı aktiviteyi gizlemeye çalışıyor olabilir.", "score": 20},
            "domain_age_new": {"text": "Domain çok yeni oluşturulmuş. Yeni domainler genellikle kötü amaçlı faaliyetler için kullanılır ve kısa ömürlü olabilir.", "score": 50},
            "domain_age_young": {"text": "Domain yaşı genç. Yeni domainler riskli olabilir ancak henüz erken aşamada.", "score": 30},
            "domain_age_moderate": {"text": "Domain yaşı orta seviyede. Dikkatli olmakta fayda var.", "score": 10},
            "domain_age_unknown": {"text": "Domain oluşturulma tarihi bulunamadı. WHOIS bilgileri gizlenmiş olabilir, bu da şüpheli bir durumdur.", "score": 20},
            "whois_error": {"text": "WHOIS sorgusu yapılamadı veya domain bulunamadı. Bu durum, alan adının gizlenmeye çalışıldığını veya mevcut olmadığını gösterebilir.", "score": 10},
            "similar_domain": {"text": "URL, bilinen meşru bir alan adına çok benziyor (typosquatting). Bu, kullanıcıları kandırmak için yapılan bir oltalama girişimi olabilir.", "score": 30},
            "punycode_detected": {"text": "Punycode (IDN) kullanımı tespit edildi. Gerçek alan adını taklit etmek için benzer görünen karakterler kullanılmış olabilir.", "score": 25},
            "ssl_expired": {"text": "SSL sertifikasının süresi dolmuş. Güvenli bağlantı sağlanamaz, bu da sitenin bakımsız veya kötü amaçlı olduğunu gösterebilir.", "score": 30},
            "ssl_soon_expire": {"text": "SSL sertifikası yakında sona erecek. Sitenin güncel olmadığını veya yenilenmesinin ihmal edildiğini gösterebilir.", "score": 10},
            "ssl_error": {"text": "SSL sertifikasında hata oluştu. Güvenli bağlantı kurulamadı veya sertifika geçersiz.", "score": 15},
            "ssl_timeout": {"text": "SSL sertifika kontrolü zaman aşımına uğradı. Sunucu yanıt vermiyor veya bağlantı sorunları var.", "score": 10},
            "ssl_connection_error": {"text": "SSL sertifika kontrolü bağlantı hatası. Ağ veya sunucu tarafında bir sorun olabilir.", "score": 10},
            "ssl_ip_address": {"text": "IP adresleri için doğrudan SSL sertifikası kontrolü genellikle geçerli değildir, çünkü sertifikalar genellikle alan adları için verilir.", "score": 10},
            "http_status_redirect": {"text": "URL yönlendirme yapıyor. Aşırı veya şüpheli yönlendirmeler kötü amaçlı olabilir.", "score": 10},
            "http_status_forbidden": {"text": "Erişim yasaklandı (403). Sitenin erişime kapalı olması veya kısıtlı olması şüpheli olabilir.", "score": 15},
            "http_status_not_found": {"text": "Sayfa bulunamadı (404). Bu, kötü amaçlı bir sitenin kaldırıldığını veya URL'nin yanlış olduğunu gösterebilir.", "score": 20},
            "http_status_server_error": {"text": "Sunucu hatası (5xx). Sunucunun düzgün çalışmadığını veya kötü amaçlı bir sunucu olduğunu gösterebilir.", "score": 30},
            "http_status_unknown": {"text": "Bilinmeyen HTTP durum kodu. Sunucudan anormal bir yanıt alındı.", "score": 20},
            "http_status_connection_error": {"text": "HTTP durumu alınamadı (Bağlantı/İstek hatası). URL'ye erişilemiyor.", "score": 10},
            "virustotal_malicious": {"text": "VirusTotal kötü amaçlı içerik buldu. Çeşitli güvenlik motorları bu URL'yi tehlikeli olarak işaretledi.", "score": 40},
            "virustotal_no_record": {"text": "VirusTotal'da URL kaydı bulunamadı. Bu yeni veya nadir bir URL olabilir, bu da riskli olabileceği anlamına gelir.", "score": 20},
            "virustotal_api_error": {"text": "VirusTotal API hatası. API anahtarınız geçersiz veya kullanım limitiniz aşılmış olabilir.", "score": 10},
            "blacklisted_domain_ip": {"text": "Bu domain/IP, yerel kara listenizde bulunuyor. Daha önce kötü amaçlı olarak işaretlenmiş demektir.", "score": 50},
            "safelisted_domain_ip": {"text": "Bu domain/IP, yerel güvenli listelerinizde bulunuyor. Güvenli kabul edilmektedir.", "score": 0}, 
        }

    def _get_config_path(self):
        script_dir = os.path.dirname(__file__)
        return os.path.join(script_dir, 'config.ini')

    def _load_config(self):
        if not os.path.exists(self.config_path):
            self.config['API_Keys'] = {'virustotal_api_key': ''}
            self.config['AnalysisSettings'] = {
                'suspicious_keywords': "login,free,update,verify,account,secure,paypal,bank,click,download",
                'suspicious_extensions': ".exe,.bat,.scr,.zip,.rar,.msi",
                'levenshtein_threshold': '1',
                'path_length_threshold': '50', 
                'encoded_char_threshold': '5' 
            }
            self.config['Files'] = {
                'blacklist_file': 'blacklist.txt',
                'real_domains_file': 'real_domains.txt',
                'history_file': 'history.txt' 
            }
            self.config['RiskThresholds'] = {
                'safe': '20',
                'suspicious': '60'
            }
            try:
                with open(self.config_path, 'w') as configfile:
                    self.config.write(configfile)
            except IOError as e:
                messagebox.showerror("Hata", f"Config dosyası oluşturulurken hata: {e}\nLütfen uygulama klasörünün yazma izinlerini kontrol edin.")
        else:
            self.config.read(self.config_path)
        
        # Yeni ayarları yükle
        self.path_length_threshold = int(self.config['AnalysisSettings'].get('path_length_threshold', '50'))
        self.encoded_char_threshold = int(self.config['AnalysisSettings'].get('encoded_char_threshold', '5'))


    def _save_config(self):
        try:
            with open(self.config_path, 'w') as configfile:
                self.config.write(configfile)
            return True
        except Exception as e:
            messagebox.showerror("Hata", f"Ayarlar kaydedilirken hata oluştu: {e}")
            return False

    def _create_widgets(self):
        header_frame = tk.Frame(self.master, bg=self.dark_blue_bg)
        header_frame.pack(pady=10, fill=tk.X)

        tk.Label(header_frame, text="CLICK PROTECTION", font=("Arial", 18, "bold"), fg=self.text_color_dark, bg=self.dark_blue_bg).pack(expand=True)

        tk.Label(self.master, text="🔗 URL veya IP Girin:", font=("Arial", 12, "bold"), fg=self.text_color_dark, bg=self.primary_bg).pack(pady=5)
        self.url_entry = tk.Entry(self.master, width=90, fg=self.text_color_light, bg=self.result_box_bg, insertbackground=self.text_color_light, font=("Arial", 10, "bold"))
        self.url_entry.pack()

        tk.Label(self.master, text="🔑 VirusTotal API Key:", font=("Arial", 12, "bold"), fg=self.text_color_dark, bg=self.primary_bg).pack(pady=3)
        self.api_entry = tk.Entry(self.master, width=90, show="*", fg=self.text_color_light, bg=self.result_box_bg, insertbackground=self.text_color_light, font=("Arial", 10, "bold"))
        self.api_entry.pack()

        self.remember_api_var = tk.BooleanVar(value=bool(self.vt_api_key))
        if self.remember_api_var.get():
            self.api_entry.insert(0, self.vt_api_key)
            self.api_entry.config(state='disabled')
        else:
            self.api_entry.insert(0, "")

        # API anahtarı hatırlama ve API anahtarı alma butonu aynı frame'de
        api_options_frame = tk.Frame(self.master, bg=self.primary_bg)
        api_options_frame.pack(pady=2)
        tk.Checkbutton(api_options_frame, text="API anahtarımı hatırla", variable=self.remember_api_var, command=self._toggle_api_entry_state, fg=self.text_color_dark, bg=self.primary_bg, selectcolor=self.dark_blue_bg).pack(side=tk.LEFT, padx=5)
        tk.Button(api_options_frame, text="API Anahtarım Yok / Ücretsiz Al", command=self._open_virustotal_apikey_page, bg=self.button_color, fg=self.button_text_color, font=("Arial", 9)).pack(side=tk.LEFT, padx=5)

        btn_frame = tk.Frame(self.master, bg=self.primary_bg)
        btn_frame.pack(pady=5)

        button_options = {'bg': self.button_color, 'fg': self.button_text_color, 'font': ("Arial", 10)}
        tk.Button(btn_frame, text="Kara Listeyi Düzenle", command=lambda: self._edit_list_file(self.blacklist_file, "Kara Liste Düzenle"), **button_options).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Güvenli Domainleri Düzenle", command=lambda: self._edit_list_file(self.real_domains_file, "Güvenli Domainleri Düzenle"), **button_options).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Ayarları Düzenle", command=self._open_settings_window, **button_options).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Geçmişi Görüntüle", command=self._show_history_window, **button_options).pack(side=tk.LEFT, padx=5)

        self.result_box = scrolledtext.ScrolledText(self.master, width=90, height=18, state='disabled', fg=self.text_color_light, bg=self.result_box_bg, insertbackground=self.text_color_light)
        self.result_box.pack(pady=5, padx=10)

        self.risk_label = tk.Label(self.master, text="0% - Bilgi Yok", font=("Helvetica", 14, "bold"), bg=self.primary_bg, fg=self.text_color_dark)
        self.risk_label.pack()

        s = ttk.Style()
        s.theme_use('default')
        s.configure("white.Horizontal.TProgressbar", background=self.button_color, troughcolor=self.white_color, bordercolor=self.white_color, lightcolor=self.button_color, darkcolor=self.button_color)
        self.risk_bar = ttk.Progressbar(self.master, length=300, mode="determinate", maximum=100, style="white.Horizontal.TProgressbar")
        self.risk_bar.pack()

        self.open_in_browser_button = tk.Button(self.master, text="Tarayıcıda Aç", command=self._open_url_in_browser, font=("Arial", 10), bg=self.button_color, fg=self.button_text_color, state=tk.DISABLED)
        self.open_in_browser_button.pack(pady=(0, 5)) 

        self.check_button = tk.Button(self.master, text="Kontrol Et", command=self._start_analysis_thread, font=("Arial", 14, "bold"), bg=self.button_color, fg=self.button_text_color)
        self.check_button.pack(pady=10) 

    def _toggle_api_entry_state(self):
        if self.remember_api_var.get():
            if self.api_entry.get().strip():
                self.api_entry.config(state='disabled', show="") 
                self.config['API_Keys']['virustotal_api_key'] = self.api_entry.get().strip()
                self._save_config()
            else:
                self.api_entry.config(state='normal', show="*")
                messagebox.showinfo("Bilgi", "API anahtarını kaydetmek için lütfen bir anahtar girin.")
        else:
            self.api_entry.config(state='normal', show="*")
            if 'virustotal_api_key' in self.config['API_Keys']:
                del self.config['API_Keys']['virustotal_api_key']
                self._save_config()
            self.vt_api_key = ''
            self.api_entry.delete(0, tk.END)

    def _open_virustotal_apikey_page(self):
        """VirusTotal'ın API anahtarı alım sayfasına yönlendirir."""
        url = "https://www.virustotal.com/gui/my-apikey"
        try:
            webbrowser.open_new_tab(url)
            messagebox.showinfo("Bilgi", "VirusTotal'ın ücretsiz API anahtarı alım sayfası tarayıcınızda açıldı. Lütfen adımları takip ederek bir anahtar alın ve uygulamaya yapıştırın.")
        except Exception as e:
            messagebox.showerror("Tarayıcı Hatası", f"VirusTotal sayfası tarayıcıda açılamadı: {e}")

    def _open_settings_window(self):
        settings_window = tk.Toplevel(self.master)
        settings_window.title("Uygulama Ayarları")
        settings_window.geometry("400x500") 
        settings_window.config(bg=self.primary_bg)

        tk.Label(settings_window, text="Şüpheli Anahtar Kelimeler (virgülle ayırın):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_keywords_entry = tk.Entry(settings_window, width=50, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_keywords_entry.insert(0, ",".join(self.suspicious_keywords))
        self.settings_keywords_entry.pack()

        tk.Label(settings_window, text="Şüpheli Dosya Uzantıları (virgülle ayırın):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_extensions_entry = tk.Entry(settings_window, width=50, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_extensions_entry.insert(0, ",".join(self.suspicious_extensions))
        self.settings_extensions_entry.pack()

        tk.Label(settings_window, text="Levenshtein Benzerlik Eşiği (0-10 arası):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_levenshtein_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_levenshtein_entry.insert(0, str(self.levenshtein_threshold))
        self.settings_levenshtein_entry.pack()

        tk.Label(settings_window, text="Yol Uzunluğu Eşiği (karakter sayısı):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_path_length_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_path_length_entry.insert(0, str(self.path_length_threshold))
        self.settings_path_length_entry.pack()

        tk.Label(settings_window, text="Kodlanmış Karakter Eşiği (%):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_encoded_char_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_encoded_char_entry.insert(0, str(self.encoded_char_threshold))
        self.settings_encoded_char_entry.pack()

        tk.Label(settings_window, text="Güvenli Risk Eşiği (%):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_safe_threshold_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_safe_threshold_entry.insert(0, str(self.risk_threshold_safe))
        self.settings_safe_threshold_entry.pack()

        tk.Label(settings_window, text="Şüpheli Risk Eşiği (%):", bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)
        self.settings_suspicious_threshold_entry = tk.Entry(settings_window, width=10, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        self.settings_suspicious_threshold_entry.insert(0, str(self.risk_threshold_suspicious))
        self.settings_suspicious_threshold_entry.pack()

        tk.Button(settings_window, text="Ayarları Kaydet", command=lambda: self._save_settings(settings_window), bg=self.button_color, fg=self.button_text_color).pack(pady=10)

    def _save_settings(self, window):
        try:
            self.suspicious_keywords = [k.strip().lower() for k in self.settings_keywords_entry.get().split(',') if k.strip()]
            self.suspicious_extensions = [e.strip().lower() for e in self.settings_extensions_entry.get().split(',') if e.strip()]
            self.levenshtein_threshold = int(self.settings_levenshtein_entry.get())
            self.path_length_threshold = int(self.settings_path_length_entry.get())
            self.encoded_char_threshold = int(self.settings_encoded_char_entry.get())
            self.risk_threshold_safe = int(self.settings_safe_threshold_entry.get())
            self.risk_threshold_suspicious = int(self.settings_suspicious_threshold_entry.get())

            if not (0 <= self.levenshtein_threshold <= 10):
                raise ValueError("Levenshtein eşiği 0 ile 10 arasında olmalı.")
            if not (0 <= self.path_length_threshold <= 1000): 
                raise ValueError("Yol uzunluğu eşiği 0 ile 1000 arasında olmalı.")
            if not (0 <= self.encoded_char_threshold <= 100): 
                raise ValueError("Kodlanmış karakter eşiği 0 ile 100 arasında olmalı.")
            if not (0 <= self.risk_threshold_safe <= 100 and 0 <= self.risk_threshold_suspicious <= 100):
                raise ValueError("Risk eşikleri 0 ile 100 arasında olmalı.")
            if self.risk_threshold_safe >= self.risk_threshold_suspicious:
                raise ValueError("Güvenli eşik, şüpheli eşikten küçük olmalı.")

            self.config['AnalysisSettings']['suspicious_keywords'] = ",".join(self.suspicious_keywords)
            self.config['AnalysisSettings']['suspicious_extensions'] = ",".join(self.suspicious_extensions)
            self.config['AnalysisSettings']['levenshtein_threshold'] = str(self.levenshtein_threshold)
            self.config['AnalysisSettings']['path_length_threshold'] = str(self.path_length_threshold)
            self.config['AnalysisSettings']['encoded_char_threshold'] = str(self.encoded_char_threshold)
            self.config['RiskThresholds']['safe'] = str(self.risk_threshold_safe)
            self.config['RiskThresholds']['suspicious'] = str(self.risk_threshold_suspicious)

            self._save_config()
            messagebox.showinfo("Başarılı", "Ayarlar başarıyla kaydedildi.")
            window.destroy()
        except ValueError as ve:
            messagebox.showerror("Hata", f"Geçersiz ayar değeri: {ve}")
        except Exception as e:
            messagebox.showerror("Hata", f"Ayarlar kaydedilirken bir hata oluştu: {e}")

    def _start_analysis_thread(self):
        if self.analysis_running:
            messagebox.showinfo("Bilgi", "Analiz zaten devam ediyor, lütfen bekleyin.")
            return

        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Hata", "Lütfen bir URL veya IP girin.")
            return

        current_api_input = self.api_entry.get().strip()
        if self.remember_api_var.get():
            if current_api_input:
                self.vt_api_key = current_api_input
                if self.config['API_Keys'].get('virustotal_api_key') != self.vt_api_key:
                    self.config['API_Keys']['virustotal_api_key'] = self.vt_api_key
                    self._save_config()
                self.api_entry.config(state='disabled')
            else:
                messagebox.showwarning("Uyarı", "API anahtarını kaydetmek için lütfen bir anahtar girin.")
                self.api_entry.config(state='normal')
                return
        else:
            self.vt_api_key = current_api_input
            if 'virustotal_api_key' in self.config['API_Keys']:
                del self.config['API_Keys']['virustotal_api_key']
                self._save_config()

        self.result_box.config(state='normal')
        self.result_box.delete("1.0", tk.END)
        self.risk_bar["value"] = 0
        self.risk_label.config(text="Yükleniyor...", fg="gray")
        self.check_button.config(state=tk.DISABLED, text="Analiz Ediliyor...")
        self.open_in_browser_button.config(state=tk.DISABLED) 
        self.analysis_running = True
        self.last_analyzed_url = "" 

        analysis_thread = threading.Thread(target=self._run_analysis_in_thread, args=(url,))
        analysis_thread.start()

    def _run_analysis_in_thread(self, url):
        try:
            normalized_url = url
            if self._is_ip_address(url) and not urlparse(url).scheme:
                normalized_url = "http://" + url
            elif not urlparse(url).scheme:
                normalized_url = "http://" + url
                
            parsed_url = urlparse(normalized_url)
            if not parsed_url.hostname and not self._is_ip_address(normalized_url):
                self.master.after(0, lambda: messagebox.showerror("Hata", "Geçersiz URL veya IP adresi formatı. Hostname veya IP adresi çıkarılamadı."))
                self.master.after(0, self._reset_analysis_state)
                return

            issues, vt_analysis_data, domain, score, status, color, subdomains = self._analyze_url(normalized_url)

            self.master.after(0, self._update_gui_with_results, url, issues, vt_analysis_data, domain, score, status, color)
            self.master.after(0, self._add_to_history, url, score, status)
            self.master.after(0, self._update_open_in_browser_button, url, status) 

        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Hata", f"Analiz sırasında bir hata oluştu:\n{e}"))
            self.master.after(0, lambda: self.result_box.insert(tk.END, f"Analiz sırasında bir hata oluştu: {e}", "red"))
            self.master.after(0, lambda: self.result_box.config(state='disabled'))
        finally:
            self.master.after(0, self._reset_analysis_state)

    def _update_gui_with_results(self, original_url, issues, vt_analysis_data, domain, score, status, color):
        self.result_box.config(state='normal')
        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, f"Analiz Edilen URL/IP: {original_url}\n\n", "bold")
        self.result_box.tag_config("bold", font=("TkDefaultFont", 10, "bold"))

        for i, (line, detail_key) in enumerate(issues):
            tag = ""
            if line.startswith("🔴"): tag = "red"
            elif line.startswith("🟠"): tag = "orange"
            elif line.startswith("🟡"): tag = "yellow"
            elif line.startswith("🟢"): tag = "green_status"
            elif line.startswith("ℹ️"): tag = "info"
            elif line.startswith("🚫"): tag = "dark_red"
            elif line.startswith("✅"): tag = "green_status" 
            elif line.startswith("🔎"): tag = "purple"
            elif line.startswith("⚠️"): tag = "warning"
            
            self.result_box.insert(tk.END, line + "\n", tag)
            
            if detail_key and self.issue_details.get(detail_key):
                details = self.issue_details[detail_key]["text"]
                self.result_box.insert(tk.END, f"    (i) Detay: {details}\n", "info_detail")
                self.result_box.tag_config("info_detail", foreground=self.dark_gray_detail, font=("TkDefaultFont", 8, "italic"))

        self.result_box.tag_config("red", foreground="red")
        self.result_box.tag_config("dark_red", foreground="#8B0000")
        self.result_box.tag_config("orange", foreground="orange")
        self.result_box.tag_config("yellow", foreground="#FFD700")
        self.result_box.tag_config("green_status", foreground=self.light_green)
        self.result_box.tag_config("info", foreground="blue")
        self.result_box.tag_config("purple", foreground="purple")
        self.result_box.tag_config("warning", foreground="darkgoldenrod")

        self.result_box.insert(tk.END, "\n")
        
        self.result_box.insert(tk.END, "🔎 VirusTotal Sonucu:\n", "purple")
        if isinstance(vt_analysis_data, dict):
            self.result_box.insert(tk.END, f"Tarama Sonucu: {vt_analysis_data.get('malicious', 0)} Zararlı, {vt_analysis_data.get('suspicious', 0)} Şüpheli, {vt_analysis_data.get('harmless', 0)} Temiz, {vt_analysis_data.get('undetected', 0)} Tespit Edilmemiş.\n")
            self.result_box.insert(tk.END, f"Toplam Motor Taraması: {vt_analysis_data.get('total_scans', 0)}\n")
            if vt_analysis_data.get('engines_detected'):
                self.result_box.insert(tk.END, "Tespit Eden Motorlar (ilk 5):\n")
                for engine_detail in vt_analysis_data['engines_detected']:
                    self.result_box.insert(tk.END, f"    - {engine_detail}\n")
                if vt_analysis_data.get('more_engines_count', 0) > 0:
                    self.result_box.insert(tk.END, f"    ... ve diğer {vt_analysis_data['more_engines_count']} motor.\n")
            else:
                self.result_box.insert(tk.END, "✅ Herhangi bir zararlı veya şüpheli bulgu tespit edilmedi.\n")
        else:
            self.result_box.insert(tk.END, f"{vt_analysis_data}\n")

        self.risk_label.config(text=f"{score}% - {status}", fg=color)
        self.risk_bar["value"] = score
        self.result_box.config(state='disabled')

    def _reset_analysis_state(self):
        self.analysis_running = False
        self.check_button.config(state=tk.NORMAL, text="Kontrol Et")

    def _update_open_in_browser_button(self, url, status):
        if status == "Güvenli ✅" and not self._is_ip_address(url):
            self.open_in_browser_button.config(state=tk.NORMAL)
            self.last_analyzed_url = url
        else:
            self.open_in_browser_button.config(state=tk.DISABLED)
            self.last_analyzed_url = ""

    def _open_url_in_browser(self):
        if self.last_analyzed_url:
            try:
                webbrowser.open_new_tab(self.last_analyzed_url)
            except Exception as e:
                messagebox.showerror("Tarayıcı Hatası", f"URL tarayıcıda açılamadı: {e}")
        else:
            messagebox.showwarning("Tarayıcı Hatası", "Tarayıcıda açılacak bir URL bulunmuyor veya güvenli değil.")

    def _extract_main_domain(self, url):
        if self._is_ip_address(url) and not urlparse(url).scheme:
            url = "http://" + url
        
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return ext.domain + "." + ext.suffix
        elif self._is_ip_address(url):
            return urlparse(url).hostname if urlparse(url).hostname else url
        else: 
            return urlparse(url).hostname if urlparse(url).hostname else url


    def _extract_subdomains(self, url):
        ext = tldextract.extract(url).subdomain
        return ext.split(".") if ext else []

    def _is_ip_address(self, url_or_host):
        try:
            if "://" in url_or_host:
                host = urlparse(url_or_host).hostname
            else:
                host = url_or_host
            if not host: 
                host = url_or_host 
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _check_at_symbol(self, url):
        return "@" in url

    def _check_multiple_subdomains(self, url):
        sub = tldextract.extract(url).subdomain
        if sub:
            parts = [p for p in sub.split(".") if p and p.lower() != "www"]
            return len(parts) > 1
        return False

    def _check_keywords(self, url):
        try:
            with open(self.blacklist_file, "r") as f:
                blacklist_from_file = [line.strip().lower() for line in f if line.strip()]
        except FileNotFoundError:
            blacklist_from_file = []
            
        all_suspicious_items = self.suspicious_keywords + blacklist_from_file
        return any(keyword in url.lower() for keyword in all_suspicious_items)

    def _check_extensions(self, url):
        return any(url.lower().endswith(ext) for ext in self.suspicious_extensions)

    def _load_domains_from_file(self, filename):
        normalized_domains = set()
        try:
            script_dir = os.path.dirname(__file__)
            full_path = os.path.join(script_dir, filename)
            with open(full_path, "r", encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip().lower()
                    if stripped_line:
                        if self._is_ip_address(stripped_line):
                            normalized_domains.add(stripped_line) 
                        else:
                            extracted_info = tldextract.extract(stripped_line)
                            if extracted_info.domain and extracted_info.suffix:
                                normalized_domains.add(f"{extracted_info.domain}.{extracted_info.suffix}")
                            elif extracted_info.domain: 
                                normalized_domains.add(extracted_info.domain)
        except FileNotFoundError:
            pass
        return list(normalized_domains)

    def _save_domains_to_file(self, filename, domains):
        script_dir = os.path.dirname(__file__)
        full_path = os.path.join(script_dir, filename)
        with open(full_path, "w", encoding='utf-8') as f:
            for d in domains:
                f.write(d + "\n")

    def _is_similar_domain(self, domain, legit_domains):
        for legit in legit_domains:
            if domain == legit:
                continue
            
            dist = Levenshtein.distance(domain, legit)
            if dist <= self.levenshtein_threshold:
                return True, legit
        return False, None

    def _is_blacklisted(self, domain_or_ip):
        blacklist = self._load_domains_from_file(self.blacklist_file)
        return domain_or_ip in blacklist

    def _is_safelisted(self, domain_or_ip):
        safelist = self._load_domains_from_file(self.real_domains_file)
        if domain_or_ip in safelist:
            return True

        if not self._is_ip_address(domain_or_ip):
            main_domain = self._extract_main_domain(domain_or_ip)
            if main_domain in safelist:
                return True
        return False

    def _check_ssl_cert(self, domain_or_ip):
        try:
            ctx = ssl.create_default_context()
            host_to_connect = domain_or_ip

            if self._is_ip_address(domain_or_ip):
                return "⚠️ IP adresleri için doğrudan SSL sertifikası kontrolü genellikle geçerli değildir.", 10, "ssl_ip_address"
            
            try:
                if domain_or_ip.startswith("xn--"):
                    host_to_connect = idna.decode(domain_or_ip)
            except idna.IDNAError:
                pass 

            with socket.create_connection((host_to_connect, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host_to_connect) as ssock:
                    cert = ssock.getpeercert()
                    expire_date_str = cert.get('notAfter')
                    if not expire_date_str:
                        return "🟠 SSL Sertifikası son kullanma tarihi bulunamadı.", 10, "ssl_error"
                    
                    expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.utcnow()).days
                    if days_left < 0:
                        return f"🔴 SSL Sertifikası süresi dolmuş! ({expire_date.date()})", 30, "ssl_expired"
                    elif days_left < 30:
                        return f"🟠 SSL Sertifikası yakında sona erecek ({days_left} gün kaldı)", 10, "ssl_soon_expire"
                    else:
                        return f"🟢 SSL Sertifikası geçerli, son kullanma: {expire_date.date()}", 0, None
        except ssl.SSLError as e:
            return f"⚠️ SSL sertifika hatası: {e}", 15, "ssl_error"
        except socket.timeout:
            return "⚠️ SSL sertifika kontrolü zaman aşımına uğradı.", 10, "ssl_timeout"
        except (socket.error, ConnectionRefusedError, OSError) as e:
            return f"⚠️ SSL sertifika kontrolü bağlantı hatası: {e}", 10, "ssl_connection_error"
        except Exception as e:
            return f"⚠️ SSL sertifika kontrolü yapılamadı (Genel hata: {e})", 10, "ssl_error"

    def _check_domain_age(self, domain):
        try:
            info = whois.whois(domain)
            creation_date = None
            if isinstance(info.creation_date, list):
                creation_date = min(info.creation_date) if info.creation_date else None
            else:
                creation_date = info.creation_date

            if not creation_date:
                return "🟠 Domain oluşturulma tarihi bulunamadı.", 20, "domain_age_unknown"
            
            if not isinstance(creation_date, datetime):
                date_formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d-%b-%Y', '%Y%m%d', '%Y.%m.%d']
                parsed = False
                for fmt in date_formats:
                    try:
                        creation_date = datetime.strptime(str(creation_date).split(" ")[0], fmt.split(" ")[0])
                        parsed = True
                        break
                    except ValueError:
                        continue
                if not parsed:
                    return "⚠️ Domain oluşturulma tarihi formatı tanınamadı.", 15, "domain_age_unknown"

            age = (datetime.now() - creation_date).days

            if age < 100:
                return f"🔴 Bu domain {age} gün önce oluşturulmuş! Çok yeni ve çok riskli.", 50, "domain_age_new"
            elif age < 300:
                return f"🟠 Bu domain {age} gün önce oluşturulmuş! Riskli olabilir.", 30, "domain_age_young"
            elif age < 500:
                return f"🟡 Bu domain {age} gün önce oluşturulmuş! Dikkat etmekte fayda var.", 10, "domain_age_moderate"
            else:
                return f"🟢 Domain yaşı {age} gün – Güvenli domain yaşı.", 0, None
        except PywhoisError:
            return "⚠️ WHOIS sorgusu yapılamadı veya domain bulunamadı.", 10, "whois_error"
        except Exception as e:
            return f"⚠️ WHOIS hatası: {e}", 10, "whois_error"

    def _check_http_status(self, url_or_ip):
        HTTP_STATUS_DETAILS = {
            100: "100 Continue: Devam etmek için sunucunun cevabını bekleyin.",
            101: "101 Switching Protocols: Protokol değiştiriliyor.",
            200: "200 OK: Sayfa başarıyla yüklendi.",
            201: "201 Created: Kaynak başarıyla oluşturuldu.",
            202: "202 Accepted: İstek kabul edildi, ancak işlem henüz tamamlanmadı.",
            204: "204 No Content: İstek başarıyla işlendi, ancak döndürülecek içerik yok.",
            301: "301 Moved Permanently: Kalıcı yönlendirme.",
            302: "302 Found: Geçici yönlendirme.",
            303: "303 See Other: Diğer bir URL'ye yönlendirme.",
            304: "304 Not Modified: Kaynak değişmedi.",
            307: "307 Temporary Redirect: Geçici yönlendirme.",
            308: "308 Permanent Redirect: Kalıcı yönlendirme.",
            400: "400 Bad Request: İstemci tarafından gönderilen istekte hata var.",
            401: "401 Unauthorized: Kimlik doğrulaması gereklidir.",
            403: "403 Forbidden: Sunucu isteği anladı ancak yetki verilmedi.",
            404: "404 Not Found: İstenen sayfa bulunamadı.",
            405: "405 Method Not Allowed: Kullanılan HTTP metodu desteklenmiyor.",
            406: "406 Not Acceptable: Sunucu, istemcinin talep ettiği biçimde yanıt üretemez.",
            408: "408 Request Timeout: İstek zaman aşımına uğradı.",
            409: "409 Conflict: İstek bir sunucu çakışması nedeniyle tamamlanamadı.",
            410: "410 Gone: Kaynak kalıcı olarak kaldırıldı.",
            429: "429 Too Many Requests: Çok fazla istek gönderildi, geçici olarak engellendi.",
            500: "500 Internal Server Error: Sunucuda hata oluştu.",
            501: "501 Not Implemented: Sunucu isteği yerine getiremez.",
            502: "502 Bad Gateway: Ağ geçidi sunucusu geçersiz bir yanıt aldı.",
            503: "503 Service Unavailable: Sunucu şu anda hizmet veremiyor.",
            504: "504 Gateway Timeout: Ağ geçidi sunucusu zaman aşımına uğradı.",
        }
        
        try_urls = []
        parsed_url_scheme = urlparse(url_or_ip).scheme
        
        if not parsed_url_scheme: 
            try_urls.append("https://" + url_or_ip)
            try_urls.append("http://" + url_or_ip)
        else: 
            try_urls.append(url_or_ip)

        for attempt_url in try_urls:
            try:
                response = requests.head(attempt_url, timeout=5, allow_redirects=True, verify=True)  
                status_code = response.status_code
                description = HTTP_STATUS_DETAILS.get(status_code, "Durum açıklaması bulunamadı.")

                if 200 <= status_code < 300: 
                    return f"📡 HTTP durum kodu: {status_code} (OK)\nℹ️ Açıklama: {description}", 0, None
                elif 300 <= status_code < 400: 
                    return f"🟡 HTTP durum kodu: {status_code} (Yönlendirme)\nℹ️ Açıklama: {description}", 10, "http_status_redirect"
                elif status_code == 403:
                    return f"🟠 HTTP durum kodu: 403 (Erişim yasaklandı)\nℹ️ Açıklama: {description}", 15, "http_status_forbidden"
                elif status_code == 404:
                    return f"🔴 HTTP durum kodu: 404 (Sayfa bulunamadı)\nℹ️ Açıklama: {description}", 20, "http_status_not_found"
                elif 500 <= status_code < 600: 
                    return f"🔴 HTTP durum kodu: {status_code} (Sunucu hatası)\nℹ️ Açıklama: {description}", 30, "http_status_server_error"
                else: 
                    return f"🟠 HTTP durum kodu: {status_code} (Bilinmeyen durum)\nℹ️ Açıklama: {description}", 20, "http_status_unknown"
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
            
        return f"🔴 HTTP durumu alınamadı (Bağlantı/İstek hatası). URL'ye erişilemiyor.", 10, "http_status_connection_error"

    def _check_suspicious_parameters(self, url):
        return bool(re.search(r"[?&](tm_campaign=|ap_id=|aaid=|gclid=|utm_source=|utm_medium=|utm_campaign=|utm_term=|utm_content=)", url))

    def _check_punycode(self, domain):
        try:
            if domain.startswith("xn--"):
                decoded_domain = idna.decode(domain)
                return True, f"🔴 Punycode (IDN) kullanımı tespit edildi: '{domain}' -> '{decoded_domain}'", "punycode_detected"
            return False, None, None
        except idna.IDNAError as e:
            return False, f"⚠️ Punycode çözülürken hata: {e}", None

    def _check_path_and_query_anomalies(self, url):
        parsed = urlparse(url)
        issues = []
        total_score = 0

        path = parsed.path
        if len(path) > self.path_length_threshold:
            issues.append(("🟠 URL yolu çok uzun. (+10)", "long_path"))
            total_score += 10

        encoded_chars = re.findall(r"%[0-9a-fA-F]{2}", path + parsed.query)
        if len(path + parsed.query) > 0:
            percentage_encoded = (len(encoded_chars) / len(path + parsed.query)) * 100
            if percentage_encoded > self.encoded_char_threshold:
                issues.append(("🟠 URL yolu veya sorgu parametrelerinde yüksek oranda kodlanmış karakter var. (+15)", "encoded_path_query"))
                total_score += 15

        query_params = parse_qs(parsed.query)
        for key, values in query_params.items():
            for value in values:
                decoded_value = requests.utils.unquote(value) 
                if re.search(r"[^a-zA-Z0-9\-\._~]", decoded_value) and len(decoded_value) > 10: 
                    issues.append(("🔴 Sorgu parametrelerinde şifrelenmiş/anlamsız değerler var. (+20)", "obfuscated_parameters"))
                    total_score += 20
                    break 
            if "obfuscated_parameters" in [issue[1] for issue in issues]:
                break 

        return issues, total_score

    def _virus_total_scan(self, target):
        if not self.vt_api_key:
            return "ℹ️ VirusTotal API Key girilmedi veya yapılandırma dosyasından yüklenemedi.\n" \
                   "Lütfen bir API anahtarı girin ve kaydetmeyi deneyin."

        headers = {"x-apikey": self.vt_api_key}
        result_data = {
            "status": "error",
            "message": "",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_scans": 0,
            "engines_detected": [],
            "more_engines_count": 0
        }

        try:
            parsed = urlparse(target)
            
            vt_url = ""
            resource_type = ""

            if self._is_ip_address(target):
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
                resource_type = "IP Adresi"
            elif not parsed.scheme: 
                url_to_encode = "http://" + target
                encoded = base64.urlsafe_b64encode(url_to_encode.encode()).decode().strip("=")
                vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
                resource_type = "URL"
            else: 
                encoded = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
                vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
                resource_type = "URL"
            
            r = requests.get(vt_url, headers=headers, timeout=15)

            if r.status_code == 200:
                data = r.json().get("data", {})
                if not data:
                    result_data["status"] = "warning"
                    result_data["message"] = f"⚠️ VirusTotal'da {resource_type} için veri bulunamadı."
                    return result_data

                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                result_data["malicious"] = stats.get("malicious", 0)
                result_data["suspicious"] = stats.get("suspicious", 0)
                result_data["harmless"] = stats.get("harmless", 0)
                result_data["undetected"] = stats.get("undetected", 0)
                result_data["total_scans"] = result_data["malicious"] + result_data["suspicious"] + result_data["harmless"] + result_data["undetected"]
                
                analysis_results = attributes.get("last_analysis_results", {})
                all_engines_detected = []
                for engine, result in analysis_results.items():
                    if result["category"] in ["malicious", "suspicious"]:
                        all_engines_detected.append(f"{engine}: {result['result']} ({result['category']})")
                
                result_data["engines_detected"] = all_engines_detected[:5]
                result_data["more_engines_count"] = len(all_engines_detected) - len(result_data["engines_detected"])

                if result_data["malicious"] > 0 or result_data["suspicious"] > 0:
                    result_data["status"] = "malicious"
                    result_data["message"] = "🚫 VirusTotal kötü amaçlı/şüpheli içerik buldu."
                else:
                    result_data["status"] = "harmless"
                    result_data["message"] = "✅ VirusTotal: Herhangi bir zararlı veya şüpheli bulgu tespit edilmedi."
                return result_data

            elif r.status_code == 401:
                result_data["message"] = "⚠️ VirusTotal API anahtarı geçersiz veya yetkisiz."
            elif r.status_code == 403:
                result_data["message"] = "⚠️ VirusTotal erişim engellendi (403 Forbidden). API çağrı limitinizi kontrol edin."
            elif r.status_code == 404:
                result_data["message"] = f"⚠️ VirusTotal'da '{target}' için kayıt bulunamadı. Bu yeni veya nadir bir {resource_type} olabilir."
            elif r.status_code == 429:
                result_data["message"] = "⚠️ VirusTotal API çağrı limiti aşıldı (429 Too Many Requests). Lütfen bekleyin."
            else:
                result_data["message"] = f"⚠️ VirusTotal API hatası: {r.status_code} - {r.text}"

        except requests.exceptions.Timeout:
            result_data["message"] = "⚠️ VirusTotal isteği zaman aşımına uğradı (15 saniye)."
        except requests.exceptions.ConnectionError:
            result_data["message"] = "⚠️ VirusTotal bağlantı hatası. İnternet bağlantınızı kontrol edin."
        except Exception as e:
            result_data["message"] = f"⚠️ VirusTotal isteği başarısız: {e}"
            
        return result_data

    def _analyze_url(self, url):
        is_ip = self._is_ip_address(url)
        domain = ""
        subs = []

        if not is_ip:
            domain = self._extract_main_domain(url).lower()
            subs = self._extract_subdomains(url)

        total_score = 0
        issues = [] 
        
        if self._is_safelisted(domain if not is_ip else url):
            issues.append(("✅ Bu URL güvenli domainler listenizde bulunuyor. Risk puanı sıfırlandı.", "safelisted_domain_ip"))
            return issues, {}, domain, 0, "Güvenli ✅", self.light_green, subs

        legit_domains = self._load_domains_from_file(self.real_domains_file)

        if not is_ip and self._is_blacklisted(domain):
            issues.append(("🔴 Bu domain kara listede yer alıyor! (+50)", "blacklisted_domain_ip"))
            total_score += 50
        elif is_ip and self._is_blacklisted(url):
            issues.append(("🔴 Bu IP adresi kara listede yer alıyor! (+50)", "blacklisted_domain_ip"))
            total_score += 50

        if is_ip:
            issues.append(("🔴 URL doğrudan bir IP adresi. (+20)", "ip_in_url"))
            total_score += 20
        elif self._is_ip_address(urlparse(url).hostname):
            issues.append(("🔴 URL hostname kısmında bir IP adresi içeriyor. (+20)", "ip_in_url"))
            total_score += 20
            
        if self._check_at_symbol(url):
            issues.append(("🔴 '@' karakteri içeriyor (Kullanıcı adı/şifre gizleme girişimi olabilir). (+20)", "at_symbol"))
            total_score += 20
        if not is_ip and self._check_multiple_subdomains(url):
            issues.append(("🟠 Çok fazla subdomain var. (+10)", "multiple_subdomains"))
            total_score += 10
        if self._check_keywords(url):
            issues.append(("🟠 URL şüpheli kelimeler içeriyor. (+10)", "suspicious_keywords"))
            total_score += 10
        if self._check_extensions(url):
            issues.append(("🔴 URL tehlikeli dosya uzantısı içeriyor. (+40)", "suspicious_extensions"))
            total_score += 40
        if self._check_suspicious_parameters(url):
            issues.append(("🟠 URL'de şüpheli takip parametreleri tespit edildi. (+15)", "suspicious_parameters"))
            total_score += 15
        
        path_query_issues, path_query_score = self._check_path_and_query_anomalies(url)
        issues.extend(path_query_issues)
        total_score += path_query_score

        if not is_ip:
            age_result, age_score, age_detail_key = self._check_domain_age(domain)
            issues.append((f"{age_result} (+{age_score})", age_detail_key))
            total_score += age_score

            similar, legit_match = self._is_similar_domain(domain, legit_domains)
            if similar:
                issues.append((f"🔴 Phishing benzeri domain tespit edildi (typosquatting): '{domain}' ↔ '{legit_match}' (+30)", "similar_domain"))
                total_score += 30
            
            punycode_detected, punycode_message, punycode_detail_key = self._check_punycode(domain)
            if punycode_detected:
                issues.append((punycode_message + " (+25)", punycode_detail_key)) 
                total_score += 25

            ssl_result, ssl_score, ssl_detail_key = self._check_ssl_cert(domain)
            issues.append((f"{ssl_result} (+{ssl_score})", ssl_detail_key))
            total_score += ssl_score
        else: 
            ssl_result, ssl_score, ssl_detail_key = self._check_ssl_cert(url)
            issues.append((f"{ssl_result} (+{ssl_score})", ssl_detail_key))
            total_score += ssl_score
            issues.append(("ℹ️ IP adresi olduğu için Domain Yaşı ve Benzer Domain kontrolü atlandı.", None))

        http_result, http_score, http_detail_key = self._check_http_status(url)
        issues.append((f"{http_result} (+{http_score})", http_detail_key))
        total_score += http_score

        vt_analysis_data = self._virus_total_scan(url)
        
        if isinstance(vt_analysis_data, dict):
            if vt_analysis_data.get('status') == "malicious":
                issues.append(("🚫 VirusTotal kötü amaçlı içerik buldu. (+40)", "virustotal_malicious"))
                total_score += 40
            elif vt_analysis_data.get('status') == "warning" and "kayıt bulunamadı" in vt_analysis_data.get('message', ''):
                issues.append(("⚠️ VirusTotal kaydı bulunamadı (Yeni/nadir olabilir). (+20)", "virustotal_no_record"))
                total_score += 20
            elif vt_analysis_data.get('status') == "error":
                issues.append((f"⚠️ VirusTotal hatası: {vt_analysis_data.get('message', 'Bilinmeyen hata')}", "virustotal_api_error"))
                total_score += 10
        else:
            issues.append((vt_analysis_data, "virustotal_api_error"))

        total_score = max(0, min(100, total_score))

        if total_score <= self.risk_threshold_safe:
            status = "Güvenli ✅"
            color = self.light_green
        elif total_score <= self.risk_threshold_suspicious:
            status = "Şüpheli ⚠️"
            color = "orange"
        else:
            status = "Tehlikeli 🚫"
            color = "red"

        return issues, vt_analysis_data, domain, total_score, status, color, subs

    def _edit_list_file(self, filename, title):
        def save_changes():
            items_to_save = listbox.get(0, tk.END)
            try:
                self._save_domains_to_file(filename, items_to_save)
                messagebox.showinfo("Başarılı", f"{title} başarıyla kaydedildi.")
                edit_window.destroy()
            except Exception as e:
                messagebox.showerror("Hata", f"Dosya kaydedilirken hata oluştu: {e}")

        def add_item():
            new_item = entry.get().strip().lower() 
            if new_item:
                normalized_new_item = ""
                if self._is_ip_address(new_item):
                    normalized_new_item = new_item
                else:
                    extracted_info = tldextract.extract(new_item)
                    if extracted_info.domain and extracted_info.suffix:
                        normalized_new_item = f"{extracted_info.domain}.{extracted_info.suffix}"
                    elif extracted_info.domain:
                        normalized_new_item = extracted_info.domain
                
                if normalized_new_item and normalized_new_item not in listbox.get(0, tk.END):
                    listbox.insert(tk.END, normalized_new_item)
                    entry.delete(0, tk.END)
                elif not normalized_new_item and not self._is_ip_address(new_item):
                    messagebox.showwarning("Uyarı", "Geçerli bir domain veya IP adresi girin.")
                else:
                    messagebox.showwarning("Uyarı", "Bu öğe zaten listede mevcut.")
            else:
                messagebox.showwarning("Uyarı", "Boş giriş eklenemez.")


        def delete_selected():
            selected_indices = listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("Uyarı", "Silmek için bir öğe seçin.")
                return
            for index in reversed(selected_indices):
                listbox.delete(index)

        items = self._load_domains_from_file(filename) 

        edit_window = tk.Toplevel(self.master)
        edit_window.title(title)
        edit_window.geometry("450x450")
        edit_window.config(bg=self.primary_bg)

        listbox = tk.Listbox(edit_window, selectmode=tk.EXTENDED, width=60, bg=self.result_box_bg, fg=self.text_color_light, selectbackground=self.button_color, selectforeground=self.button_text_color)
        listbox.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        for item in items:
            listbox.insert(tk.END, item)

        entry_frame = tk.Frame(edit_window, bg=self.primary_bg)
        entry_frame.pack(fill=tk.X, padx=10)

        entry = tk.Entry(entry_frame, bg=self.result_box_bg, fg=self.text_color_light, insertbackground=self.text_color_light)
        entry.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=5)

        add_btn = tk.Button(entry_frame, text="Ekle", command=add_item, bg=self.button_color, fg=self.button_text_color)
        add_btn.pack(side=tk.LEFT, padx=5)

        btn_frame = tk.Frame(edit_window, bg=self.primary_bg)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        delete_btn = tk.Button(btn_frame, text="Seçiliyi Sil", command=delete_selected, bg=self.button_color, fg=self.button_text_color)
        delete_btn.pack(side=tk.LEFT)

        save_btn = tk.Button(btn_frame, text="Kaydet", command=save_changes, bg=self.button_color, fg=self.button_text_color)
        save_btn.pack(side=tk.RIGHT)

    def _load_generic_list_from_file(self, filename):
        items = []
        try:
            script_dir = os.path.dirname(__file__)
            full_path = os.path.join(script_dir, filename)
            with open(full_path, "r", encoding='utf-8') as f:
                items = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            pass
        except Exception as e:
            messagebox.showwarning("Dosya Okuma Hatası", f"'{filename}' dosyası okunurken hata oluştu: {e}")
            pass
        return items

    def _load_history(self):
        history_file_path = self.config['Files']['history_file']
        script_dir = os.path.dirname(__file__)
        full_path = os.path.join(script_dir, history_file_path)

        if not os.path.exists(full_path):
            try:
                with open(full_path, 'w', encoding='utf-8') as f:
                    pass
                self.history = [] 
                print(f"Bilgi: '{history_file_path}' dosyası bulunamadı. Yeni boş bir geçmiş dosyası oluşturuldu.")
                return 
            except Exception as e:
                messagebox.showwarning("Geçmiş Dosyası Oluşturma Hatası", f"Geçmiş dosyası oluşturulurken hata oluştu: {e}")
                self.history = [] 
                return

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                self.history = [] 
                for line in f:
                    parts = line.strip().split(';')
                    if len(parts) == 3:
                        try:
                            self.history.append({'url': parts[0], 'score': int(parts[1]), 'status': parts[2]})
                        except ValueError:
                            print(f"Uyarı: Geçersiz geçmiş kaydı atlandı: {line.strip()}")
                    else:
                        print(f"Uyarı: Geçersiz formatta geçmiş kaydı atlandı: {line.strip()}")
        except Exception as e:
            messagebox.showwarning("Geçmiş Yükleme Hatası", f"Geçmiş dosyası yüklenirken hata oluştu: {e}")
            self.history = [] 

    def _save_history(self):
        history_file_path = self.config['Files']['history_file']
        script_dir = os.path.dirname(__file__)
        full_path = os.path.join(script_dir, history_file_path)
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                for entry in self.history:
                    f.write(f"{entry['url']};{entry['score']};{entry['status']}\n")
        except Exception as e:
            messagebox.showwarning("Geçmiş Kaydetme Hatası", f"Geçmiş dosyası kaydedilirken hata oluştu: {e}")

    def _add_to_history(self, url, score, status):
        for i, entry in enumerate(self.history):
            if entry['url'] == url:
                del self.history[i]
                break
            
        self.history.insert(0, {'url': url, 'score': score, 'status': status})
        
        if len(self.history) > self.MAX_HISTORY_SIZE:
            self.history = self.history[:self.MAX_HISTORY_SIZE]
            
        self._save_history()

    def _show_history_window(self):
        history_window = tk.Toplevel(self.master)
        history_window.title("Son Aramalar Geçmişi")
        history_window.geometry("600x400")
        history_window.config(bg=self.primary_bg)

        tk.Label(history_window, text="Son Analiz Edilen URL'ler:", font=("Arial", 12, "bold"), bg=self.primary_bg, fg=self.text_color_dark).pack(pady=5)

        history_listbox = tk.Listbox(history_window, width=80, height=15, bg=self.result_box_bg, fg=self.text_color_light, selectbackground=self.button_color, selectforeground=self.button_text_color)
        history_listbox.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        if not self.history:
            history_listbox.insert(tk.END, "Geçmişte kayıt bulunamadı.")
        else:
            for entry in self.history:
                history_listbox.insert(tk.END, f"[{entry['status']}] {entry['url']} (Risk: {entry['score']}%)")
        
        def load_selected_from_history():
            selected_indices = history_listbox.curselection()
            if selected_indices:
                selected_index = selected_indices[0]
                selected_url = self.history[selected_index]['url']
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, selected_url)
                history_window.destroy()
                self._start_analysis_thread()

        load_button = tk.Button(history_window, text="Seçili URL'yi Yükle ve Kontrol Et", command=load_selected_from_history, bg=self.button_color, fg=self.button_text_color)
        load_button.pack(pady=5)

        def delete_selected_from_history():
            selected_indices = history_listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("Uyarı", "Silmek için geçmişten bir öğe seçin.", parent=history_window)
                return

            if messagebox.askyesno("Seçiliyi Sil", "Seçili öğeyi geçmişten silmek istediğinizden emin misiniz?", parent=history_window):
                for index in sorted(selected_indices, reverse=True):
                    del self.history[index]
                    history_listbox.delete(index)
                self._save_history()
                messagebox.showinfo("Başarılı", "Seçili öğe başarıyla silindi.", parent=history_window)
                if not self.history:
                    history_listbox.insert(tk.END, "Geçmişte kayıt bulunamadı.")

        delete_selected_button = tk.Button(history_window, text="Seçiliyi Geçmişten Sil", command=delete_selected_from_history, bg=self.button_color, fg=self.button_text_color)
        delete_selected_button.pack(pady=5)

        def clear_history_confirm():
            if messagebox.askyesno("Geçmişi Temizle", "Tüm geçmişi temizlemek istediğinizden emin misiniz?", parent=history_window):
                self.history = []
                self._save_history()
                history_listbox.delete(0, tk.END)
                history_listbox.insert(tk.END, "Geçmiş temizlendi.")

        clear_all_button = tk.Button(history_window, text="Tüm Geçmişi Temizle", command=clear_history_confirm, bg=self.button_color, fg=self.button_text_color)
        clear_all_button.pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = URLAnalyzerApp(root)
    root.mainloop()