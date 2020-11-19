import logging

import aiogram.utils.markdown as md
from aiogram import Bot, Dispatcher, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters import Text
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.types import ParseMode
from aiogram.utils import executor

import json
from os.path import exists
from bip32 import BIP32
import hashlib
import bech32
import pyqrcode
import asyncio

import aiohttp
from io import BytesIO

from datetime import datetime

# Bitcoin-related initialization
XPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

bip32 = BIP32.from_xpub(XPUB)
ESPLORA_API = "https://blockstream.info/api/"
PENDING_TIME = 1800
prefix = 'bc'
witver=0x00
gap = 5

# Some Bitcoin-related functions


def hash160(data):
    """Return ripemd160(sha256(data))"""
    rh = hashlib.new('ripemd160', hashlib.sha256(data).digest())
    return rh.digest()


if bip32.network == "test":
    ESPLORA_API = "https://blockstream.info/testnet/api/"
    prefix = 'tb'


def derive_address(index: int):
    pub = bip32.get_pubkey_from_path(f"m/0/{index}")
    # legacy
    # base58.b58encode_check(hash160(pubkey))
    witprog = hash160(pub)
    return bech32.encode(prefix, witver, witprog)


# TODO: Erase later
for i in range(0, 10):
    print(derive_address(i))


async def fetch_url(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as request:
            if not request.status == 200:
                raise ValueError("Endpoint at {} returned {} ({})"
                           .format(request, request.status,
                                   request.text))
            try:
                return await request.json()
            except:
                return await request.text()


async def get_chaininfo():
    blockhash_url = "{}/block-height/0".format(ESPLORA_API)
    blockcount_url = "{}/blocks/tip/height".format(ESPLORA_API)
    chains = {
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f":
            "main",
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943":
            "test",
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206":
            "regtest"
    }

    genesis_json = await fetch_url(blockhash_url)
    tip_json = await fetch_url(blockcount_url)

    if genesis_json not in chains.keys():
        raise ValueError("Unsupported network")

    return {
        "chain": bip32.network,
        "blockcount": genesis_json,
        "headercount": tip_json,
        "ibd": False,
    }

lock = asyncio.Lock()
missed_indexes = asyncio.Queue()
sent_indexes = asyncio.Queue()
last_index = asyncio.Queue()
balances = {}

#

logging.basicConfig(level=logging.DEBUG)

API_TOKEN = ''


bot = Bot(token=API_TOKEN)

# For example use simple MemoryStorage for Dispatcher.
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)


# States
class Form(StatesGroup):
    sleep = State()
    receive = State()
    result = State()


@dp.message_handler(commands='start')
async def cmd_start(message: types.Message, state: FSMContext):
    """
    Conversation's entry point
    """
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, selective=True)
    markup.add("Активировать")
    await state.set_state(Form.sleep)
    logging.debug("activated")
    await message.reply("Это бот пожертвований. Активируйте его и затем нажмите кнопку, чтобы получить Биткоин-адрес", reply_markup=markup)


# You can use state '*' if you need to handle all states
@dp.message_handler(state='*', commands='cancel')
@dp.message_handler(Text(equals='cancel', ignore_case=True), state='*')
async def cancel_handler(message: types.Message, state: FSMContext):
    """
    Allow user to cancel any action
    """
    current_state = await state.get_state()
    if current_state is None:
        return

    logging.info('Cancelling state %r', current_state)
    # Cancel state and inform user about it
    await state.finish()
    # And remove keyboard (just in case)
    await message.reply('Cancelled.', reply_markup=types.ReplyKeyboardRemove())


@dp.message_handler(lambda message: message.text in ["Активировать", "Получить адрес", "Транзакция в сети", "Отмена"], state=None)
async def restart(message: types.Message, state: FSMContext):
    """
    In this example gender has to be one of: Male, Female, Other.
    """
    await message.reply("Перезапуск")
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, selective=True)
    markup.add("Получить адрес")
    await state.set_state(Form.receive)
    await bot.send_message(message.chat.id, "Бот готов к работе", reply_markup=markup)


@dp.message_handler(lambda message: message.text == "Активировать", state='*')
async def process_result(message: types.Message, state: FSMContext):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, selective=True)
    markup.add("Получить адрес")
    await state.set_state(Form.receive)
    await bot.send_message(message.chat.id, "Бот готов к работе", reply_markup=markup)


@dp.message_handler(lambda message: message.text == "Получить адрес", state=Form.receive)
async def process_result(message: types.Message, state: FSMContext):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, selective=True)
    markup.add("Отмена")
    address = ""
    idx = 0
    while True:
        if missed_indexes.qsize() > 0:
            idx = await missed_indexes.get()
            logging.debug(f"taking index from missed_indexes: {idx}")
        else:
            l_index = await last_index.get()
            idx = l_index
            l_index += 1
            await last_index.put(l_index)
            logging.debug(f"taking last_index {idx}, incrementing {l_index}")
        address = derive_address(idx)
        logging.debug(f"checking balance: {address}")
        url = "{}/address/{}".format(ESPLORA_API, address)
        info = await fetch_url(url)
        recieved_amt = info['chain_stats']['funded_txo_sum']
        logging.debug(f"received balance: {recieved_amt}")
        if recieved_amt > 0:
            logging.debug(f"repeating address generation with {l_index}")
            continue
        else:
            logging.debug(f"sending address {address}")
            break
    qr = pyqrcode.create(address)
    stream = BytesIO()
    qr.png(stream, scale=3)
    await bot.send_photo(message.chat.id, stream.getvalue(), caption=f"bitcoin:{address}")
    await bot.send_message(message.chat.id, "Нажмите Отмена, если хотите отказаться", reply_markup=markup)
    awaitable = {'id': message.chat.id,
                 'idx': idx,
                 'address': address,
                 'ts': datetime.now().timestamp()}
    await sent_indexes.put(awaitable)
    logging.debug(f"awaitables updated with {idx}")
    return await state.set_state(Form.result)


@dp.message_handler(lambda message: message.text == "Отмена", state=Form.result)
async def process_result(message: types.Message, state: FSMContext):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, selective=True)
    markup.add("Активировать")
    await message.reply("Спасибо за внимание. Возвращаясь, обязательно запросите новый адрес", reply_markup=markup)
    uid = message.chat.id
    refresh = []
    for i in range(0, sent_indexes.qsize()):
        awaitable = await sent_indexes.get()
        if awaitable['id'] == uid:
            logging.debug(f"found free address {awaitable['address']}")
            await missed_indexes.put(awaitable['idx'])
            break
        else:
            refresh.append(awaitable)
    for a in awaitable:
        await sent_indexes.put(a)
    await state.finish()


async def clearing():
    logging.info("clearing loop started")
    try:
        while True:
            logging.debug("address clearing loop")
            if sent_indexes.qsize() > 0:
                awaitable = await sent_indexes.get()
                if datetime.now().timestamp() - awaitable['ts'] < PENDING_TIME:
                    await sent_indexes.put(awaitable)
                    logging.debug(f"pending time wasn't exceeded. continue...")
                    await asyncio.sleep(PENDING_TIME/100)
                    continue
                address = awaitable['address']
                logging.debug(f"clearing address {address}")
                url = "{}/address/{}".format(ESPLORA_API, address)
                info = await fetch_url(url)
                recieved = info['chain_stats']['funded_txo_sum']
                pending = info["mempool_stats"]["funded_txo_sum"]
                logging.debug(f"received balance: {recieved}")
                logging.debug(f"pending balance: {pending}")
                markup = types.ReplyKeyboardMarkup(resize_keyboard=True,
                                                   selective=True)
                markup.add("Активировать")
                if recieved > 0 or pending > 0:
                    await bot.send_message(awaitable['id'],
                                           f"Бот видит транзакцию на адрес {address}. Спасибо",
                                           reply_markup=markup)
                else:
                    await bot.send_message(awaitable['id'],
                                           f"Мы не получили платёж в разумное время, "
                                           f"{address} возвращается в пул адресов. "
                                           f"Если измените решение, запросите новый адрес",
                                           reply_markup=markup)
                    await missed_indexes.put(awaitable['idx'])
            else:
                await asyncio.sleep(PENDING_TIME)
    except Exception as e:
        logging.error(f"clearing loop started crash: {e}")


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    wallet_state = {}
    l_index = 0
    balances = {}
    if exists("dump.dat"):
        logging.info(f"reading wallet state")
        with open("dump.dat", "r") as dump:
            wallet_state = json.loads(dump.read())
            if 'balances' in wallet_state:
                balances = wallet_state['balances']
                logging.info(f"wallet total addresses {len(balances.keys())}")
                for a in balances.keys():
                    logging.info(f"loaded {a}: {balances[a]}")
            if 'last_index' in wallet_state:
                l_index = wallet_state['last_index']
                logging.info(f"last index: {l_index}")
            else:
                l_index = 0

    info = loop.run_until_complete(get_chaininfo())
    logging.info(f"received blockchain info {info['chain']} height {info['headercount']}")

    for i in range(0, l_index + gap):
        address = derive_address(i)
        url = "{}/address/{}".format(ESPLORA_API, address)
        info = loop.run_until_complete(fetch_url(url))
        balance = info["chain_stats"]["funded_txo_sum"] - \
                  info["chain_stats"]["spent_txo_sum"]
        pending = info["mempool_stats"]["funded_txo_sum"] - \
                  info["mempool_stats"]["spent_txo_sum"]
        used = False
        if info["chain_stats"]["funded_txo_sum"] > 0 or pending > 0:
            used = True
            if l_index - i < -1:
                loop.run_until_complete(missed_indexes.put(i))
                logging.info(f"missed index {i} address {address} added")
            else:
                l_index = i + 1
                logging.info(f"adjusting last index {l_index}")
            if address not in balances.keys():
                balances[address] = {
                    'in': info["chain_stats"]["funded_txo_sum"],
                    'out': info["chain_stats"]["spent_txo_sum"]
                }
        logging.info(f"{i}: {address} balance {balance}, {pending}; {used}")
    loop.run_until_complete(last_index.put(l_index))
    future = asyncio.run_coroutine_threadsafe(clearing(), loop)
    logging.info("Launching telegram bot")
    # Start long-polling
    executor.start_polling(dp, skip_updates=True)
    try:
        result = future.result(timeout=1.)
    except TimeoutError:
        print('The coroutine took too long, cancelling the task...')
        future.cancel()
    except Exception as exc:
        print(f'The coroutine raised an exception: {exc!r}')
    else:
        print(f'The coroutine returned: {result!r}')
    logging.info(f"dumping wallet state")
    dump_list = []
    for i in range(0, missed_indexes.qsize()):
        idx = loop.run_until_complete(missed_indexes.get())
        dump_list.append(idx)
    logging.debug(f"dumping {len(dump_list)} addresses")
    wallet_state['indexes'] = dump_list
    wallet_state['last_index'] = loop.run_until_complete(last_index.get())
    wallet_state['balances'] = balances
    with open("dump.dat", "w") as dump:
        dump.write(json.dumps(wallet_state))
    logging.info(f"wallet saved")
