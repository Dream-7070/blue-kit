import os
import json
import logging
import asyncio

try:
    from telegram import Update, Document
    from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler
except ImportError:
    pass

from .model import build
from .render import render_html, render_docx

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

(LANG, TITLE, ORG, TEAM, ANALYST, LOGS_OR_IOCS, EXEC_SUMMARY, RECOMMENDATIONS) = range(8)

async def start(update, context):
    await update.message.reply_text(
        "DIQQAT: Musobaqada AI va internet cheklangan bo'lishi mumkin — bu bot faqat MASHQ uchun. "
        "Rasmiy ish uchun offline `bk report` yoki web UI.\n\n"
        "Tilni tanlang (uz / ru / en):"
    )
    context.user_data.clear()
    return LANG

async def lang(update, context):
    context.user_data['lang'] = update.message.text.strip().lower()
    if context.user_data['lang'] not in ['uz', 'ru', 'en']: context.user_data['lang'] = 'uz'
    await update.message.reply_text("Hisobot sarlavhasi (Title):")
    return TITLE

async def title(update, context):
    context.user_data['title'] = update.message.text
    await update.message.reply_text("Tashkilot (Org):")
    return ORG

async def org(update, context):
    context.user_data['org'] = update.message.text
    await update.message.reply_text("Jamoa (Team):")
    return TEAM

async def team(update, context):
    context.user_data['team'] = update.message.text
    await update.message.reply_text("Tahlilchi (Analyst):")
    return ANALYST

async def analyst(update, context):
    context.user_data['analyst'] = update.message.text
    await update.message.reply_text(
        "logs.json va triage.json fayllarini yuboring (agar bo'lsa), yoki 'skip' deb yozing:"
    )
    context.user_data['logs'] = {}
    context.user_data['resp'] = {}
    return LOGS_OR_IOCS

async def handle_files(update, context):
    msg = update.message
    if msg.document:
        doc = msg.document
        file = await context.bot.get_file(doc.file_id)
        content = await file.download_as_bytearray()
        try:
            data = json.loads(content.decode('utf-8'))
            if 'timeline' in data or 'iocs' in data:
                context.user_data['logs'] = data
                await msg.reply_text("Logs yuklandi. Yana fayl yuboring yoki 'skip' deng.")
                return LOGS_OR_IOCS
            elif 'findings' in data:
                context.user_data['resp'] = data
                await msg.reply_text("Triage yuklandi. Yana fayl yuboring yoki 'skip' deng.")
                return LOGS_OR_IOCS
        except Exception:
            await msg.reply_text("JSON o'qib bo'lmadi.")
            return LOGS_OR_IOCS
            
    if msg.text and msg.text.lower() == 'skip':
        await msg.reply_text("Qisqacha mazmun (Exec Summary) kiriting yoki 'auto' deb yozing:")
        return EXEC_SUMMARY
    
    await msg.reply_text("Fayl yoki 'skip' kutilyapti.")
    return LOGS_OR_IOCS

async def exec_summary(update, context):
    t = update.message.text
    context.user_data['exec_summary'] = "" if t.lower() == 'auto' else t
    await update.message.reply_text("Tavsiyalar (Recommendations) kiriting yoki 'skip' deb yozing:")
    return RECOMMENDATIONS

async def recommendations(update, context):
    t = update.message.text
    context.user_data['recommendations'] = "" if t.lower() == 'skip' else t
    
    answers = {
        'title': context.user_data.get('title'),
        'org': context.user_data.get('org'),
        'team': context.user_data.get('team'),
        'analyst': context.user_data.get('analyst'),
        'exec_summary': context.user_data.get('exec_summary'),
        'recommendations': context.user_data.get('recommendations'),
    }
    
    await update.message.reply_text("Hisobot yasalmoqda...")
    
    mod = build(context.user_data.get('logs', {}), context.user_data.get('resp', {}), answers)
    h = render_html(mod, context.user_data['lang'])
    
    with open('report.html', 'w', encoding='utf-8') as f:
        f.write(h)
    
    with open('report.html', 'rb') as f:
        await update.message.reply_document(f)
        
    try:
        render_docx(mod, context.user_data['lang'], 'report.docx')
        with open('report.docx', 'rb') as f:
            await update.message.reply_document(f)
    except Exception:
        pass
        
    return ConversationHandler.END

async def cancel(update, context):
    await update.message.reply_text("Bekor qilindi.")
    return ConversationHandler.END

def run_bot(token):
    app = Application.builder().token(token).build()
    
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            LANG: [MessageHandler(filters.TEXT & ~filters.COMMAND, lang)],
            TITLE: [MessageHandler(filters.TEXT & ~filters.COMMAND, title)],
            ORG: [MessageHandler(filters.TEXT & ~filters.COMMAND, org)],
            TEAM: [MessageHandler(filters.TEXT & ~filters.COMMAND, team)],
            ANALYST: [MessageHandler(filters.TEXT & ~filters.COMMAND, analyst)],
            LOGS_OR_IOCS: [MessageHandler(filters.Document.ALL | filters.TEXT & ~filters.COMMAND, handle_files)],
            EXEC_SUMMARY: [MessageHandler(filters.TEXT & ~filters.COMMAND, exec_summary)],
            RECOMMENDATIONS: [MessageHandler(filters.TEXT & ~filters.COMMAND, recommendations)],
        },
        fallbacks=[CommandHandler("cancel", cancel)]
    )
    app.add_handler(conv)
    app.run_polling()
