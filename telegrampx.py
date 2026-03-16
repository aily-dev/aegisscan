import json
import time
import asyncio
import logging
from typing import Callable, Dict, List, Union, Optional, Any, TypeVar, BinaryIO
from dataclasses import dataclass
import requests
import httpx

# Configure logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Type definitions
T = TypeVar('T')
HandlerFunc = Callable[['Message'], None]
CallbackQueryFunc = Callable[['CallbackQuery'], None]

class TelegramBot:
    """
    A comprehensive Telegram bot library similar to telebot
    """
    def __init__(self, token: str, parse_mode: str = 'HTML', proxy_url: str = None):
        """
        Initialize the bot with the given token and optional proxy
        
        Args:
            token: Telegram bot token
            parse_mode: Default parse mode for messages (HTML, Markdown, MarkdownV2)
            proxy_url: Optional SOCKS5 proxy URL (e.g., socks5://username:password@host:port)
        """
        self.token = token
        self.api_url = f"https://api.telegram.org/bot{token}/"
        self.file_url = f"https://api.telegram.org/file/bot{token}/"
        self.parse_mode = parse_mode

        # تنظیم پروکسی برای درخواست‌ها
        self.session = requests.Session()
        self.async_client = httpx.AsyncClient()

        if proxy_url:
            proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
            self.session.proxies.update(proxies)
            self.async_client = httpx.AsyncClient(proxies=proxies)

        # Command handlers
        self.message_handlers = []
        self.callback_query_handlers = []
        self.next_step_handlers = {}

        # Polling variables
        self.is_polling = False
        self.polling_offset = 0
        self.polling_timeout = 30
        self.polling_limit = 100

    def _make_request(self, method: str, params: Dict = None, files: Dict = None) -> Dict:
        """
        Make a request to the Telegram API
        
        Args:
            method: API method name
            params: Parameters for the API call
            files: Files to upload
            
        Returns:
            API response as dictionary
        """
        url = f"{self.api_url}{method}"
        
        try:
            if files:
                response = self.session.post(url, data=params, files=files)
            else:
                response = self.session.post(url, json=params)
            
            response.raise_for_status()
            result = response.json()
            
            if not result.get('ok'):
                logger.error(f"API error: {result.get('description')}")
                raise Exception(f"Telegram API error: {result.get('description')}")
            
            return result.get('result')

        except requests.RequestException as e:
            logger.error(f"Request error: {e}")
            raise

    async def _make_async_request(self, method: str, params: Dict = None, files: Dict = None) -> Dict:
        """
        Make an asynchronous request to the Telegram API
        
        Args:
            method: API method name
            params: Parameters for the API call
            files: Files to upload
            
        Returns:
            API response as dictionary
        """
        url = f"{self.api_url}{method}"
        
        try:
            if files:
                response = await self.async_client.post(url, data=params, files=files)
            else:
                response = await self.async_client.post(url, json=params)
            
            response.raise_for_status()
            result = response.json()
            
            if not result.get('ok'):
                logger.error(f"API error: {result.get('description')}")
                raise Exception(f"Telegram API error: {result.get('description')}")
            
            return result.get('result')

        except httpx.RequestError as e:
            logger.error(f"Async request error: {e}")
            raise
    # Bot information methods
    def get_me(self) -> Dict:
        """Get information about the bot"""
        return self._make_request('getMe')
    
    async def get_me_async(self) -> Dict:
        """Get information about the bot asynchronously"""
        return await self._make_async_request('getMe')
    
    # Message sending methods
    def send_message(self, chat_id: Union[int, str], text: str, 
                    parse_mode: str = None, 
                    disable_web_page_preview: bool = False,
                    disable_notification: bool = False,
                    reply_to_message_id: int = None,
                    reply_markup: Dict = None) -> 'Message':
        """
        Send text message
        
        Args:
            chat_id: Chat ID
            text: Message text
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            disable_web_page_preview: Disable link previews
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_web_page_preview': disable_web_page_preview,
            'disable_notification': disable_notification
        }
        
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        result = self._make_request('sendMessage', params)
        return Message.from_dict(result)
    
    async def send_message_async(self, chat_id: Union[int, str], text: str, 
                               parse_mode: str = None,
                               disable_web_page_preview: bool = False,
                               disable_notification: bool = False,
                               reply_to_message_id: int = None,
                               reply_markup: Dict = None) -> 'Message':
        """
        Send text message asynchronously
        
        Args:
            chat_id: Chat ID
            text: Message text
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            disable_web_page_preview: Disable link previews
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_web_page_preview': disable_web_page_preview,
            'disable_notification': disable_notification
        }
        
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        result = await self._make_async_request('sendMessage', params)
        return Message.from_dict(result)
    def reply_to(self, chat_id: int, message: str, reply_to_message_id: int = None):
        """
        Send a reply message to a specific chat.
        
        Args:
            chat_id: ID of the chat where the message will be sent
            message: The message text to send
            reply_to_message_id: ID of the message to reply to (optional)
        """
        params = {
            'chat_id': chat_id,
            'text': message,
            'reply_to_message_id': reply_to_message_id,
            'parse_mode': self.parse_mode,
        }
        
        return self._make_request('sendMessage', params)
    def send_photo(self, chat_id: Union[int, str], photo: Union[str, BinaryIO],
                 caption: str = None, parse_mode: str = None,
                 disable_notification: bool = False,
                 reply_to_message_id: int = None,
                 reply_markup: Dict = None) -> 'Message':
        """
        Send photo
        
        Args:
            chat_id: Chat ID
            photo: Photo URL or file object
            caption: Photo caption
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_notification': disable_notification
        }
        
        if caption:
            params['caption'] = caption
            
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        files = None
        if isinstance(photo, str) and (photo.startswith('http') or photo.startswith('https')):
            params['photo'] = photo
        else:
            files = {'photo': photo}
            
        result = self._make_request('sendPhoto', params, files)
        return Message.from_dict(result)
    
    async def send_photo_async(self, chat_id: Union[int, str], photo: Union[str, BinaryIO],
                            caption: str = None, parse_mode: str = None,
                            disable_notification: bool = False,
                            reply_to_message_id: int = None,
                            reply_markup: Dict = None) -> 'Message':
        """
        Send photo asynchronously
        
        Args:
            chat_id: Chat ID
            photo: Photo URL or file object
            caption: Photo caption
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_notification': disable_notification
        }
        
        if caption:
            params['caption'] = caption
            
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        files = None
        if isinstance(photo, str) and (photo.startswith('http') or photo.startswith('https')):
            params['photo'] = photo
        else:
            files = {'photo': photo}
            
        result = await self._make_async_request('sendPhoto', params, files)
        return Message.from_dict(result)
    def leave_chat(self, chat_id: Union[int, str]) -> bool:
        """
        Leave a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            True on success
        """
        params = {'chat_id': chat_id}
        result = self._make_request('leaveChat', params)
        return result

    def set_chat_title(self, chat_id: Union[int, str], title: str) -> bool:
        """
        Set the title of a chat
        
        Args:
            chat_id: Chat ID
            title: New chat title
            
        Returns:
            True on success
        """
        params = {
            'chat_id': chat_id,
            'title': title
        }
        result = self._make_request('setChatTitle', params)
        return result

    def set_chat_description(self, chat_id: Union[int, str], description: str) -> bool:
        """
        Set the description of a chat
        
        Args:
            chat_id: Chat ID
            description: New chat description
            
        Returns:
            True on success
        """
        params = {
            'chat_id': chat_id,
            'description': description
        }
        result = self._make_request('setChatDescription', params)
        return result

    def pin_chat_message(self, chat_id: Union[int, str], message_id: int, disable_notification: bool = False) -> bool:
        """
        Pin a message in a chat
        
        Args:
            chat_id: Chat ID
            message_id: Message ID to pin
            disable_notification: Disable notification for the pin
            
        Returns:
            True on success
        """
        params = {
            'chat_id': chat_id,
            'message_id': message_id,
            'disable_notification': disable_notification
        }
        result = self._make_request('pinChatMessage', params)
        return result

    def unpin_chat_message(self, chat_id: Union[int, str], message_id: int = None) -> bool:
        """
        Unpin a message in a chat
        
        Args:
            chat_id: Chat ID
            message_id: Message ID to unpin (optional)
            
        Returns:
            True on success
        """
        params = {'chat_id': chat_id}
        if message_id:
            params['message_id'] = message_id
        result = self._make_request('unpinChatMessage', params)
        return result

    def unpin_all_chat_messages(self, chat_id: Union[int, str]) -> bool:
        """
        Unpin all messages in a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            True on success
        """
        params = {'chat_id': chat_id}
        result = self._make_request('unpinAllChatMessages', params)
        return result

    def set_chat_photo(self, chat_id: Union[int, str], photo: BinaryIO) -> bool:
        """
        Set the photo of a chat
        
        Args:
            chat_id: Chat ID
            photo: Photo file object
            
        Returns:
            True on success
        """
        params = {'chat_id': chat_id}
        files = {'photo': photo}
        result = self._make_request('setChatPhoto', params, files)
        return result

    def delete_chat_photo(self, chat_id: Union[int, str]) -> bool:
        """
        Delete the photo of a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            True on success
        """
        params = {'chat_id': chat_id}
        result = self._make_request('deleteChatPhoto', params)
        return result
    def send_video(self, chat_id: Union[int, str], video: Union[str, BinaryIO],
                 caption: str = None, parse_mode: str = None,
                 duration: int = None, width: int = None, height: int = None,
                 thumb: Union[str, BinaryIO] = None, supports_streaming: bool = True,
                 disable_notification: bool = False,
                 reply_to_message_id: int = None,
                 reply_markup: Dict = None) -> 'Message':
        """
        Send video
        
        Args:
            chat_id: Chat ID
            video: Video URL or file object
            caption: Video caption
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            duration: Video duration in seconds
            width: Video width
            height: Video height
            thumb: Thumbnail URL or file object
            supports_streaming: Enable streaming
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'parse_mode': parse_mode or self.parse_mode,
            'supports_streaming': supports_streaming,
            'disable_notification': disable_notification
        }
        
        if caption:
            params['caption'] = caption
            
        if duration:
            params['duration'] = duration
            
        if width:
            params['width'] = width
            
        if height:
            params['height'] = height
            
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        files = {}
        if isinstance(video, str) and (video.startswith('http') or video.startswith('https')):
            params['video'] = video
        else:
            files['video'] = video
            
        if thumb:
            if isinstance(thumb, str) and (thumb.startswith('http') or thumb.startswith('https')):
                params['thumb'] = thumb
            else:
                files['thumb'] = thumb
                
        result = self._make_request('sendVideo', params, files if files else None)
        return Message.from_dict(result)
    
    def send_audio(self, chat_id: Union[int, str], audio: Union[str, BinaryIO],
                 caption: str = None, parse_mode: str = None,
                 duration: int = None, performer: str = None, title: str = None,
                 thumb: Union[str, BinaryIO] = None,
                 disable_notification: bool = False,
                 reply_to_message_id: int = None,
                 reply_markup: Dict = None) -> 'Message':
        """
        Send audio file
        
        Args:
            chat_id: Chat ID
            audio: Audio URL or file object
            caption: Audio caption
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            duration: Audio duration in seconds
            performer: Audio performer
            title: Audio title
            thumb: Thumbnail URL or file object
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_notification': disable_notification
        }
        
        if caption:
            params['caption'] = caption
            
        if duration:
            params['duration'] = duration
            
        if performer:
            params['performer'] = performer
            
        if title:
            params['title'] = title
            
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        files = {}
        if isinstance(audio, str) and (audio.startswith('http') or audio.startswith('https')):
            params['audio'] = audio
        else:
            files['audio'] = audio
            
        if thumb:
            if isinstance(thumb, str) and (thumb.startswith('http') or thumb.startswith('https')):
                params['thumb'] = thumb
            else:
                files['thumb'] = thumb
                
        result = self._make_request('sendAudio', params, files if files else None)
        return Message.from_dict(result)
    
    def send_voice(self, chat_id: Union[int, str], voice: Union[str, BinaryIO],
                 caption: str = None, parse_mode: str = None,
                 duration: int = None,
                 disable_notification: bool = False,
                 reply_to_message_id: int = None,
                 reply_markup: Dict = None) -> 'Message':
        """
        Send voice message
        
        Args:
            chat_id: Chat ID
            voice: Voice URL or file object
            caption: Voice caption
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            duration: Voice duration in seconds
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_notification': disable_notification
        }
        
        if caption:
            params['caption'] = caption
            
        if duration:
            params['duration'] = duration
            
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        files = None
        if isinstance(voice, str) and (voice.startswith('http') or voice.startswith('https')):
            params['voice'] = voice
        else:
            files = {'voice': voice}
            
        result = self._make_request('sendVoice', params, files)
        return Message.from_dict(result)
    
    def send_document(self, chat_id: Union[int, str], document: Union[str, BinaryIO],
                    caption: str = None, parse_mode: str = None,
                    thumb: Union[str, BinaryIO] = None,
                    disable_notification: bool = False,
                    reply_to_message_id: int = None,
                    reply_markup: Dict = None) -> 'Message':
        """
        Send document (file)
        
        Args:
            chat_id: Chat ID
            document: Document URL or file object
            caption: Document caption
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            thumb: Thumbnail URL or file object
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_notification': disable_notification
        }
        
        if caption:
            params['caption'] = caption
            
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        files = {}
        if isinstance(document, str) and (document.startswith('http') or document.startswith('https')):
            params['document'] = document
        else:
            files['document'] = document
            
        if thumb:
            if isinstance(thumb, str) and (thumb.startswith('http') or thumb.startswith('https')):
                params['thumb'] = thumb
            else:
                files['thumb'] = thumb
                
        result = self._make_request('sendDocument', params, files if files else None)
        return Message.from_dict(result)
    
    def send_animation(self, chat_id: Union[int, str], animation: Union[str, BinaryIO],
                      caption: str = None, parse_mode: str = None,
                      duration: int = None, width: int = None, height: int = None,
                      thumb: Union[str, BinaryIO] = None,
                      disable_notification: bool = False,
                      reply_to_message_id: int = None,
                      reply_markup: Dict = None) -> 'Message':
        """
        Send animation (GIF)
        
        Args:
            chat_id: Chat ID
            animation: Animation URL or file object
            caption: Animation caption
            parse_mode: Parse mode (HTML, Markdown, MarkdownV2)
            duration: Animation duration in seconds
            width: Animation width
            height: Animation height
            thumb: Thumbnail URL or file object
            disable_notification: Send silently
            reply_to_message_id: Message ID to reply to
            reply_markup: Keyboard markup (InlineKeyboardMarkup or ReplyKeyboardMarkup)
            
        Returns:
            Message object
        """
        params = {
            'chat_id': chat_id,
            'parse_mode': parse_mode or self.parse_mode,
            'disable_notification': disable_notification
        }
        
        if caption:
            params['caption'] = caption
            
        if duration:
            params['duration'] = duration
            
        if width:
            params['width'] = width
            
        if height:
            params['height'] = height
            
        if reply_to_message_id:
            params['reply_to_message_id'] = reply_to_message_id
            
        if reply_markup:
            params['reply_markup'] = json.dumps(reply_markup)
            
        files = {}
        if isinstance(animation, str) and (animation.startswith('http') or animation.startswith('https')):
            params['animation'] = animation
        else:
            files['animation'] = animation
            
        if thumb:
            if isinstance(thumb, str) and (thumb.startswith('http') or thumb.startswith('https')):
                params['thumb'] = thumb
            else:
                files['thumb'] = thumb
                
        result = self._make_request('sendAnimation', params, files if files else None)
        return Message.from_dict(result)
    
    # Chat action methods
    def send_chat_action(self, chat_id: Union[int, str], action: str) -> bool:
        """
        Send chat action (typing, uploading photo, etc.)
        
        Args:
            chat_id: Chat ID
            action: Action type (typing, upload_photo, record_video, upload_video, record_audio,
                    upload_audio, upload_document, find_location, record_video_note, upload_video_note)
                    
        Returns:
            True on success
        """
        params = {
            'chat_id': chat_id,
            'action': action
        }
        
        result = self._make_request('sendChatAction', params)
        return result
    
    # Message handling methods
    def register_message_handler(self, handler: HandlerFunc, 
                               commands: List[str] = None,
                               content_types: List[str] = None,
                               regexp: str = None,
                               func: Callable = None):
        """
        Register a message handler
        
        Args:
            handler: Handler function
            commands: List of commands to handle
            content_types: List of content types to handle
            regexp: Regular expression to match
            func: Custom filter function
        """
        if content_types is None:
            content_types = ['text']
            
        self.message_handlers.append({
            'handler': handler,
            'commands': commands,
            'content_types': content_types,
            'regexp': regexp,
            'func': func
        })
        
    def register_next_step_handler(self, message: 'Message', handler: HandlerFunc):
        """
        Register a handler for the next message from the user
        
        Args:
            message: Message object
            handler: Handler function
        """
        chat_id = message.chat.id
        user_id = message.from_user.id if message.from_user else None
        
        key = f"{chat_id}_{user_id}" if user_id else str(chat_id)
        self.next_step_handlers[key] = handler
        
    def register_callback_query_handler(self, handler: CallbackQueryFunc, 
                                      func: Callable = None,
                                      data: str = None):
        """
        Register a callback query handler
        
        Args:
            handler: Handler function
            func: Custom filter function
            data: Callback data to match
        """
        self.callback_query_handlers.append({
            'handler': handler,
            'func': func,
            'data': data
        })
        
    def _process_updates(self, updates: List[Dict]):
        """
        Process updates from Telegram
        
        Args:
            updates: List of updates
        """
        for update in updates:
            if 'message' in update:
                self._process_message(Message.from_dict(update['message']))
            elif 'callback_query' in update:
                self._process_callback_query(CallbackQuery.from_dict(update['callback_query']))
                
    def _process_message(self, message: 'Message'):
        """
        Process a message update
        
        Args:
            message: Message object
        """
        # First, check for next step handler
        chat_id = message.chat.id
        user_id = message.from_user.id if message.from_user else None
        
        key = f"{chat_id}_{user_id}" if user_id else str(chat_id)
        if key in self.next_step_handlers:
            handler = self.next_step_handlers.pop(key)
            try:
                handler(message)
                return
            except Exception as e:
                logger.error(f"Error in next step handler: {e}")
                
        # Then check regular message handlers
        for handler_info in self.message_handlers:
            if self._should_process_message(message, handler_info):
                try:
                    handler_info['handler'](message)
                    return
                except Exception as e:
                    logger.error(f"Error in message handler: {e}")
                    
    def _should_process_message(self, message: 'Message', handler_info: Dict) -> bool:
        """
        Check if a message should be processed by a handler
        
        Args:
            message: Message object
            handler_info: Handler information
            
        Returns:
            True if the message should be processed
        """
        # Check content type
        content_types = handler_info['content_types']
        if content_types and not self._message_matches_content_types(message, content_types):
            return False
            
        # Check commands
        commands = handler_info.get('commands')
        if commands and not self._message_matches_commands(message, commands):
            return False
            
        # Check regexp
        regexp = handler_info.get('regexp')
        if regexp and not self._message_matches_regexp(message, regexp):
            return False
            
        # Check custom filter
        func = handler_info.get('func')
        if func and not func(message):
            return False
            
        return True
        
    def _message_matches_content_types(self, message: 'Message', content_types: List[str]) -> bool:
        """
        Check if a message matches the specified content types
        
        Args:
            message: Message object
            content_types: List of content types
            
        Returns:
            True if the message matches
        """
        if 'text' in content_types and message.text:
            return True
        if 'photo' in content_types and message.photo:
            return True
        if 'video' in content_types and message.video:
            return True
        if 'audio' in content_types and message.audio:
            return True
        if 'document' in content_types and message.document:
            return True
        if 'voice' in content_types and message.voice:
            return True
        if 'animation' in content_types and message.animation:
            return True
        if 'sticker' in content_types and message.sticker:
            return True
        
        return False
        
    def _message_matches_commands(self, message: 'Message', commands: List[str]) -> bool:
        """
        Check if a message matches the specified commands
        
        Args:
            message: Message object
            commands: List of commands
            
        Returns:
            True if the message matches
        """
        if not message.text:
            return False
            
        for command in commands:
            if message.text.startswith(f'/{command}') or message.text.startswith(f'/{command}@'):
                return True
                
        return False
        
    def _message_matches_regexp(self, message: 'Message', regexp: str) -> bool:
        """
        Check if a message matches the specified regular expression
        
        Args:
            message: Message object
            regexp: Regular expression
            
        Returns:
            True if the message matches
        """
        import re
        
        if not message.text:
            return False
            
        return bool(re.match(regexp, message.text))
        
    def _process_callback_query(self, callback_query: 'CallbackQuery'):
        """
        Process a callback query update
        
        Args:
            callback_query: CallbackQuery object
        """
        for handler_info in self.callback_query_handlers:
            if self._should_process_callback_query(callback_query, handler_info):
                try:
                    handler_info['handler'](callback_query)
                    return
                except Exception as e:
                    logger.error(f"Error in callback query handler: {e}")
                    
    def _should_process_callback_query(self, callback_query: 'CallbackQuery', handler_info: Dict) -> bool:
        """
        Check if a callback query should be processed by a handler
        
        Args:
            callback_query: CallbackQuery object
            handler_info: Handler information
            
        Returns:
            True if the callback query should be processed
        """
        # Check data
        data = handler_info.get('data')
        if data and not callback_query.data == data:
            return False
            
        # Check custom filter
        func = handler_info.get('func')
        if func and not func(callback_query):
            return False
            
        return True
    
    # Polling methods
    def polling(self, none_stop: bool = False, interval: int = 0, timeout: int = 30):
        """
        Start polling updates from Telegram
        
        Args:
            none_stop: Don't stop polling on exceptions
            interval: Polling interval
            timeout: Polling timeout
        """
        self.is_polling = True
        self.polling_timeout = timeout
        
        logger.info("Starting polling...")
        
        while self.is_polling:
            try:
                self._get_updates()
            except Exception as e:
                logger.error(f"Polling error: {e}")
                if not none_stop:
                    self.is_polling = False
                    raise
            
            if interval:
                time.sleep(interval)
                
    def stop_polling(self):
        """Stop polling"""
        self.is_polling = False
        
    def _get_updates(self):
        """Get updates from Telegram"""
        params = {
            'offset': self.polling_offset,
            'timeout': self.polling_timeout,
            'limit': self.polling_limit
        }
        
        updates = self._make_request('getUpdates', params)
        
        if updates:
            self.polling_offset = updates[-1]['update_id'] + 1
            self._process_updates(updates)
    
    # Keyboard methods
    @staticmethod
    def create_reply_keyboard(buttons: List[List[str]], resize_keyboard: bool = True,
                            one_time_keyboard: bool = False) -> Dict:
        """
        Create a reply keyboard
        
        Args:
            buttons: List of button rows
            resize_keyboard: Resize the keyboard to the minimal size
            one_time_keyboard: Hide the keyboard after the user presses a button
            
        Returns:
            Reply keyboard markup dictionary
        """
        return {
            'keyboard': buttons,
            'resize_keyboard': resize_keyboard,
            'one_time_keyboard': one_time_keyboard
        }
        
    @staticmethod
    def create_inline_keyboard(buttons: List[List[Dict]]) -> Dict:
        """
        Create an inline keyboard
        
        Args:
            buttons: List of button rows (each button is a dictionary with text and callback_data)
            
        Returns:
            Inline keyboard markup dictionary
        """
        return {'inline_keyboard': buttons}
        
    @staticmethod
    def create_inline_button(text: str, callback_data: str = None, url: str = None) -> Dict:
        """
        Create an inline keyboard button
        
        Args:
            text: Button text
            callback_data: Callback data
            url: URL to open
            
        Returns:
            Button dictionary
        """
        button = {'text': text}
        
        if callback_data:
            button['callback_data'] = callback_data
        elif url:
            button['url'] = url
            
        return button
        
    # File methods
    def get_file(self, file_id: str) -> Dict:
        """
        Get file information
        
        Args:
            file_id: File ID
            
        Returns:
            File information
        """
        params = {'file_id': file_id}
        return self._make_request('getFile', params)
        
    def download_file(self, file_path: str) -> bytes:
        """
        Download a file
        
        Args:
            file_path: File path from getFile
            
        Returns:
            File content
        """
        url = f"{self.file_url}{file_path}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.content
    def get_chat_administrators(self, chat_id: Union[int, str]) -> List[Dict]:
        """
        Get the administrators of a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            List of chat administrators
        """
        params = {'chat_id': chat_id}
        return self._make_request('getChatAdministrators', params)
    
    

    def get_chat_member(self, chat_id: Union[int, str], user_id: int) -> Dict:
        """
        Get information about a chat member
        
        Args:
            chat_id: Chat ID
            user_id: User ID
            
        Returns:
            Chat member information
        """
        params = {
            'chat_id': chat_id,
            'user_id': user_id
        }
        return self._make_request('getChatMember', params)
    def get_user_profile_photos(self, user_id: int, offset: int = 0, limit: int = 100) -> Dict:
        """
        Get a list of profile pictures for a user
        
        Args:
            user_id: User ID
            offset: Sequential number of the first photo to be returned
            limit: Limits the number of photos to be retrieved (1-100)
            
        Returns:
            UserProfilePhotos object
        """
        params = {
            'user_id': user_id,
            'offset': offset,
            'limit': limit
        }
        return self._make_request('getUserProfilePhotos', params)
    
    def get_sticker_set(self, name: str) -> Dict:
        """
        Get a sticker set
        
        Args:
            name: Name of the sticker set
            
        Returns:
            StickerSet object
        """
        params = {'name': name}
        return self._make_request('getStickerSet', params)
    
    def upload_sticker_file(self, user_id: int, png_sticker: BinaryIO) -> Dict:
        """
        Upload a .png file with a sticker for later use in createNewStickerSet and addStickerToSet methods
        
        Args:
            user_id: User ID
            png_sticker: .png file with the sticker
            
        Returns:
            File object
        """
        params = {'user_id': user_id}
        files = {'png_sticker': png_sticker}
        return self._make_request('uploadStickerFile', params, files)
    
    def create_new_sticker_set(self, user_id: int, name: str, title: str, png_sticker: Union[str, BinaryIO], emojis: str) -> bool:
        """
        Create a new sticker set
        
        Args:
            user_id: User ID
            name: Sticker set name
            title: Sticker set title
            png_sticker: .png file with the sticker or URL
            emojis: One or more emoji corresponding to the sticker
            
        Returns:
            True on success
        """
        params = {
            'user_id': user_id,
            'name': name,
            'title': title,
            'emojis': emojis
        }
        
        files = None
        if isinstance(png_sticker, str) and (png_sticker.startswith('http') or png_sticker.startswith('https')):
            params['png_sticker'] = png_sticker
        else:
            files = {'png_sticker': png_sticker}
            
        return self._make_request('createNewStickerSet', params, files)
    
    def add_sticker_to_set(self, user_id: int, name: str, png_sticker: Union[str, BinaryIO], emojis: str) -> bool:
        """
        Add a new sticker to a set created by the bot
        
        Args:
            user_id: User ID
            name: Sticker set name
            png_sticker: .png file with the sticker or URL
            emojis: One or more emoji corresponding to the sticker
            
        Returns:
            True on success
        """
        params = {
            'user_id': user_id,
            'name': name,
            'emojis': emojis
        }
        
        files = None
        if isinstance(png_sticker, str) and (png_sticker.startswith('http') or png_sticker.startswith('https')):
            params['png_sticker'] = png_sticker
        else:
            files = {'png_sticker': png_sticker}
            
        return self._make_request('addStickerToSet', params, files)
    
    def set_sticker_position_in_set(self, sticker: str, position: int) -> bool:
        """
        Move a sticker in a set created by the bot to a specific position
        
        Args:
            sticker: File identifier of the sticker
            position: New sticker position in the set, zero-based
            
        Returns:
            True on success
        """
        params = {
            'sticker': sticker,
            'position': position
        }
        return self._make_request('setStickerPositionInSet', params)
    
    def delete_sticker_from_set(self, sticker: str) -> bool:
        """
        Delete a sticker from a set created by the bot
        
        Args:
            sticker: File identifier of the sticker
            
        Returns:
            True on success
        """
        params = {'sticker': sticker}
        return self._make_request('deleteStickerFromSet', params)
    def get_chat_member_count(self, chat_id: Union[int, str]) -> int:
        """
        Get the number of members in a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            Number of members
        """
        params = {'chat_id': chat_id}
        return self._make_request('getChatMemberCount', params)
    # User and chat methods
    def get_chat(self, chat_id: Union[int, str]) -> Dict:
        """
        Get information about a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            Chat information
        """
        params = {'chat_id': chat_id}
        return self._make_request('getChat', params)
        
    def get_chat_administrators(self, chat_id: Union[int, str]) -> List[Dict]:
        """
        Get the administrators of a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            List of chat administrators
        """
        params = {'chat_id': chat_id}
        return self._make_request('getChatAdministrators', params)
        
    def get_chat_member(self, chat_id: Union[int, str], user_id: int) -> Dict:
        """
        Get information about a chat member
        
        Args:
            chat_id: Chat ID
            user_id: User ID
            
        Returns:
            Chat member information
        """
        params = {
            'chat_id': chat_id,
            'user_id': user_id
        }
        return self._make_request('getChatMember', params)
        
    def get_chat_member_count(self, chat_id: Union[int, str]) -> int:
        """
        Get the number of members in a chat
        
        Args:
            chat_id: Chat ID
            
        Returns:
            Number of members
        """
        params = {'chat_id': chat_id}
        return self._make_request('getChatMemberCount', params)


# Data class definitions
@dataclass
class User:
    """Telegram user"""
    id: int
    is_bot: bool
    first_name: str
    last_name: Optional[str] = None
    username: Optional[str] = None
    language_code: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'User':
        """Create a User object from dictionary"""
        return cls(
            id=data.get('id'),
            is_bot=data.get('is_bot'),
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            username=data.get('username'),
            language_code=data.get('language_code')
        )


@dataclass
class Chat:
    """Telegram chat"""
    id: int
    type: str
    title: Optional[str] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Chat':
        """Create a Chat object from dictionary"""
        return cls(
            id=data.get('id'),
            type=data.get('type'),
            title=data.get('title'),
            username=data.get('username'),
            first_name=data.get('first_name'),
            last_name=data.get('last_name')
        )


@dataclass
class Message:
    """Telegram message"""
    message_id: int
    chat: Chat
    date: int
    from_user: Optional[User] = None
    text: Optional[str] = None
    photo: Optional[List[Dict]] = None
    video: Optional[Dict] = None
    audio: Optional[Dict] = None
    document: Optional[Dict] = None
    voice: Optional[Dict] = None
    animation: Optional[Dict] = None
    sticker: Optional[Dict] = None
    reply_to_message: Optional['Message'] = None
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Message':
        """Create a Message object from dictionary"""
        reply_to_message = None
        if data.get('reply_to_message'):
            reply_to_message = Message.from_dict(data.get('reply_to_message'))
            
        return cls(
            message_id=data.get('message_id'),
            chat=Chat.from_dict(data.get('chat')),
            date=data.get('date'),
            from_user=User.from_dict(data.get('from')) if data.get('from') else None,
            text=data.get('text'),
            photo=data.get('photo'),
            video=data.get('video'),
            audio=data.get('audio'),
            document=data.get('document'),
            voice=data.get('voice'),
            animation=data.get('animation'),
            sticker=data.get('sticker'),
            reply_to_message=reply_to_message
        )


@dataclass
class CallbackQuery:
    """Telegram callback query"""
    id: str
    from_user: User
    message: Optional[Message] = None
    inline_message_id: Optional[str] = None
    chat_instance: Optional[str] = None
    data: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'CallbackQuery':
        """Create a CallbackQuery object from dictionary"""
        return cls(
            id=data.get('id'),
            from_user=User.from_dict(data.get('from')),
            message=Message.from_dict(data.get('message')) if data.get('message') else None,
            inline_message_id=data.get('inline_message_id'),
            chat_instance=data.get('chat_instance'),
            data=data.get('data')
        )
            