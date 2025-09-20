from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import uvicorn

import json
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from jose import JWTError, jwt

# Настройка базы данных (SQLite для примера; замените на вашу БД, если нужно)
DATABASE_URL = "sqlite:///./database.db"  # Или "postgresql://user:password@localhost/dbname"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Настройки для JWT и паролей
SECRET_KEY = "your-secret-key-here"  # Замените на реальный секретный ключ (генерируйте случайно)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Модель таблицы User (добавлены club и update_ai)
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    nickname = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")  # Поле роли с дефолтным значением "user"
    club = Column(String, nullable=True)  # Новое поле для клуба (WakeUp | MIET, etc.)
    update_ai = Column(DateTime, nullable=True, default=None)  # Новое поле для даты обновления AI


# Модель таблицы Game (без изменений)
class Game(Base):
    __tablename__ = "games"

    gameId = Column(String, primary_key=True, index=True)  # gameId как первичный ключ
    data = Column(Text)  # JSON с полными данными (players, fouls, gameInfo, badgeColor)
    event_id = Column(String, index=True)  # Столбец для привязки к событиям (как строка)
    created_at = Column(DateTime, default=datetime.utcnow)


# Создание таблиц (запустите один раз; при изменении модели может потребоваться миграция)
Base.metadata.create_all(bind=engine)

# Логика для назначения роли "admin" первому пользователю в базе данных
# (если он существует и его роль не "admin", обновляем её)
db = SessionLocal()
try:
    first_user = db.query(User).first()
    if first_user and first_user.role != "admin":
        first_user.role = "admin"
        db.commit()
        print("Роль первого пользователя обновлена на 'admin'")
except Exception as e:
    print(f"Ошибка при обновлении роли первого пользователя: {str(e)}")
finally:
    db.close()


# Pydantic модель для валидации входящего JSON для игр (обновлена: добавлены поля для админа)
class SaveGameData(BaseModel):
    gameId: str = Field(..., description="Идентификатор игры (теперь первичный ключ)")
    players: list[dict] = Field(...,
                                description="Список игроков (с полями role, plus и т.д.; поле sum добавляется автоматически)")
    fouls: list[dict] = Field(..., description="Список фолов")
    gameInfo: dict = Field(..., description="Информация по игре")
    badgeColor: str = Field(..., description="Цвет бейджа")
    eventId: str = Field(..., description="ID события для привязки (как строка)")
    admin_nickname: str = Field(..., description="Никнейм админа для аутентификации")  # Новое поле
    admin_password: str = Field(..., description="Пароль админа для аутентификации")  # Новое поле


# Новая Pydantic модель для удаления игры (с проверкой админа)
class DeleteGameRequest(BaseModel):
    admin_nickname: str = Field(..., description="Никнейм админа для аутентификации")
    admin_password: str = Field(..., description="Пароль админа для аутентификации")


# Pydantic модели для пользователей (добавлено club в UserCreate)
class UserCreate(BaseModel):
    email: str
    nickname: str
    password: str
    club: str  # Новое поле для клуба (опциональное; сделайте str, если обязательное)


class UserLogin(BaseModel):
    nickname: str
    password: str


# Новая Pydantic модель для запроса на повышение пользователя до админа
class PromoteAdminRequest(BaseModel):
    admin_nickname: str = Field(..., description="Никнейм админа для аутентификации")
    admin_password: str = Field(..., description="Пароль админа для аутентификации")
    target_email: str = Field(..., description="Email пользователя, которого нужно сделать админом")
    target_nickname: str = Field(..., description="Никнейм пользователя, которого нужно сделать админом")


# Вспомогательные функции для паролей (без изменений)
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


# Вспомогательные функции для JWT (без изменений)
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# FastAPI приложение (без изменений)
app = FastAPI()

# CORS middleware для разрешения запросов с React (localhost:3000) (без изменений)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешить запросы с вашего React-сервера
    allow_credentials=True,
    allow_methods=["*"],  # Разрешить все методы (GET, POST и т.д.)
    allow_headers=["*"],  # Разрешить все заголовки
)


# Эндпоинт для регистрации (обновлён: добавлена обработка club и update_ai)
@app.post("/register")
async def register(user: UserCreate):
    db = SessionLocal()
    try:
        # Валидация клуба (если предоставлен)
        valid_clubs = ["WakeUp | MIET", "WakeUp | MIPT", "Другой"]
        if user.club and user.club not in valid_clubs:
            raise HTTPException(status_code=400, detail="Недопустимое значение клуба")

        existing_user = db.query(User).filter(
            (User.email == user.email) | (User.nickname == user.nickname)
        ).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Пользователь с таким email или nickname уже существует")

        hashed_password = get_password_hash(user.password)
        new_user = User(
            email=user.email,
            nickname=user.nickname,
            hashed_password=hashed_password,
            role="user",
            club=user.club,  # Новое поле
            update_ai=datetime.utcnow()  # Новое поле: текущая дата
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        access_token = create_access_token(
            data={"sub": new_user.nickname, "role": new_user.role},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        user_data = {
            "nickname": new_user.nickname,
            "role": new_user.role,
            # Если есть поле avatarUrl в модели User, раскомментируйте:
            # "avatarUrl": getattr(db_user, "avatarUrl", None),
        }

        return {
            "message": "Вход выполнен успешно",
            "token": access_token,
            "user": user_data
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")
    finally:
        db.close()


# Эндпоинт для входа (без изменений)
@app.post("/login")
async def login(user: UserLogin):
    db = SessionLocal()
    try:
        db_user = db.query(User).filter(User.nickname == user.nickname).first()
        if not db_user or not verify_password(user.password, db_user.hashed_password):
            raise HTTPException(status_code=400, detail="Неверный nickname или пароль")

        access_token = create_access_token(
            data={"sub": db_user.nickname, "role": db_user.role},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        user_data = {
            "nickname": db_user.nickname,
            "role": db_user.role,
            # Если есть поле avatarUrl в модели User, раскомментируйте:
            # "avatarUrl": getattr(db_user, "avatarUrl", None),
        }

        return {
            "message": "Вход выполнен успешно",
            "token": access_token,
            "user": user_data
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")
    finally:
        db.close()


# Новый эндпоинт для повышения пользователя до админа (только админы могут использовать)
@app.post("/promote_admin")
async def promote_admin(request: PromoteAdminRequest):
    db = SessionLocal()
    try:
        # Проверка админа: найти по nickname и проверить пароль и роль
        admin_user = db.query(User).filter(User.nickname == request.admin_nickname).first()
        if not admin_user:
            raise HTTPException(status_code=400, detail="Админ с таким nickname не найден")
        if not verify_password(request.admin_password, admin_user.hashed_password):
            raise HTTPException(status_code=400, detail="Неверный пароль админа")
        if admin_user.role != "admin":
            raise HTTPException(status_code=403, detail="У вас нет прав для выполнения этого действия (требуется роль admin)")

        # Найти целевого пользователя по email и nickname
        target_user = db.query(User).filter(
            (User.email == request.target_email) & (User.nickname == request.target_nickname)
        ).first()
        if not target_user:
            raise HTTPException(status_code=404, detail="Пользователь с таким email и nickname не найден")

        # Обновить роль целевого пользователя на "admin"
        target_user.role = "admin"
        db.commit()

        return {"message": f"Пользователь {target_user.nickname} успешно повышен до админа"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")
    finally:
        db.close()


# Получить список пользователей (с опциональным фильтром по event_id)
@app.get("/getUsers")
async def get_users(event_id: str = None):
    db = SessionLocal()
    try:
        if event_id is None or event_id == "1":
            users = db.query(User).all()
        else:
            games = db.query(Game).filter(Game.event_id == event_id).all()
            nicknames = set()
            for game in games:
                game_data = json.loads(game.data)
                players = game_data.get("players", [])
                for player in players:
                    name = player.get("name", "")
                    if name:
                        nicknames.add(name)
            users = db.query(User).filter(User.nickname.in_(nicknames)).all()

        users_list = [
            {
                "id": user.id,
                "email": user.email,
                "nickname": user.nickname,
                "role": user.role,
                "club": user.club  # Новое поле в ответе
            }
            for user in users
        ]

        return {"users": users_list}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения пользователей: {str(e)}")
    finally:
        db.close()


# Сохранить данные игры (обновлено: добавлена проверка админа)
@app.post("/saveGameData")
async def save_game_data(data: SaveGameData):
    print(SaveGameData)
    db = SessionLocal()
    try:
        # Проверка админа: найти по nickname и проверить пароль и роль
        admin_user = db.query(User).filter(User.nickname == data.admin_nickname).first()
        if not admin_user:
            raise HTTPException(status_code=400, detail="Админ с таким nickname не найден")
        if not verify_password(data.admin_password, admin_user.hashed_password):
            raise HTTPException(status_code=400, detail="Неверный пароль админа")
        if admin_user.role != "admin":
            raise HTTPException(status_code=403, detail="У вас нет прав для выполнения этого действия (требуется роль admin)")

        # Определяем победившую команду на основе badgeColor
        if data.badgeColor == "red":
            winning_roles = ["мирный", "шериф"]
        elif data.badgeColor == "black":
            winning_roles = ["мафия", "дон"]
        else:
            # Ничья или другой случай - никому не добавляем командные баллы
            winning_roles = []

        # Подсчёт суммы очков для каждого игрока
        for player in data.players:
            plus = player.get("plus", 0)
            minus = player.get("minus", 0)
            role = player.get("role", "")

            # Добавляем командный бонус 2.5, если роль игрока в победившей команде
            if role in winning_roles:
                plus += 2.5

            sum_points = plus - minus
            player["sum"] = sum_points

        # Формируем JSON для хранения
        game_json = json.dumps({
            "players": data.players,
            "fouls": data.fouls,
            "gameInfo": data.gameInfo,
            "badgeColor": data.badgeColor
        }, ensure_ascii=False)

        # Проверяем, существует ли игра с таким gameId
        existing_game = db.query(Game).filter(Game.gameId == data.gameId).first()
        if existing_game:
            # Обновляем данные игры
            existing_game.data = game_json
            existing_game.event_id = data.eventId
        else:
            # Создаем новую игру
            new_game = Game(
                gameId=data.gameId,
                data=game_json,
                event_id=data.eventId
            )
            db.add(new_game)
        db.commit()
        return {"message": "Данные игры сохранены успешно"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения игры: {str(e)}")
    finally:
        db.close()


# Эндпоинт для получения данных игры (без изменений)
@app.get("/getGameData/{gameId}")
async def get_game_data(gameId: str):
    db = SessionLocal()
    try:
        game = db.query(Game).filter(Game.gameId == gameId).first()
        if not game:
            raise HTTPException(status_code=404, detail="Игра не найдена")

        game_data = json.loads(game.data)
        return game_data

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения данных игры: {str(e)}")
    finally:
        db.close()


# Новый эндпоинт для удаления игры (только админы могут использовать)
@app.delete("/deleteGame/{gameId}")
async def delete_game(gameId: str, request: DeleteGameRequest):
    db = SessionLocal()
    try:
        # Проверка админа: найти по nickname и проверить пароль и роль
        admin_user = db.query(User).filter(User.nickname == request.admin_nickname).first()
        if not admin_user:
            raise HTTPException(status_code=400, detail="Админ с таким nickname не найден")
        if not verify_password(request.admin_password, admin_user.hashed_password):
            raise HTTPException(status_code=400, detail="Неверный пароль админа")
        if admin_user.role != "admin":
            raise HTTPException(status_code=403, detail="У вас нет прав для выполнения этого действия (требуется роль admin)")

        # Найти игру по gameId
        game = db.query(Game).filter(Game.gameId == gameId).first()
        if not game:
            raise HTTPException(status_code=404, detail="Игра не найдена")

        # Удалить игру
        db.delete(game)
        db.commit()

        return {"message": f"Игра с ID {gameId} успешно удалена"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка удаления игры: {str(e)}")
    finally:
        db.close()


@app.get("/getGames")
async def get_games(limit: int = 10, offset: int = 0):
    db = SessionLocal()
    try:
        total_count = db.query(Game).count()
        games = db.query(Game).order_by(Game.created_at.desc()).offset(offset).limit(limit).all()

        games_list = []
        for game in games:
            data = json.loads(game.data)
            players = data.get("players", [])
            games_list.append({
                "id": game.gameId,
                "date": game.created_at.strftime("%d.%m.%Y %H:%M"),  # Форматированная дата
                "badgeColor": data.get("badgeColor", ""),
                "players": [
                    {
                        "name": p["name"],
                        "role": p.get("role", ""),
                        "points": p.get("sum", 0)
                    }
                    for p in players
                ]
            })

        return {"games": games_list, "total_count": total_count}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения списка игр: {str(e)}")
    finally:
        db.close()


@app.get("/getRating")
async def get_rating(limit: int = Query(10, description="Количество элементов на странице"),
                     offset: int = Query(0, description="Смещение для пагинации")):
    db = SessionLocal()
    try:
        # Получаем все игры из БД
        games = db.query(Game).all()

        # Получаем всех игроков из БД (для добавления тех, кто не играл)
        all_players = db.query(User).all()
        player_names = {p.nickname for p in all_players}
        # Словарь для быстрого доступа к клубам
        clubs = {p.nickname: p.club for p in all_players}

        # Вычисляем статистику игроков
        player_stats = {}
        for game in games:
            game_data = json.loads(game.data)
            players = game_data.get("players", [])

            for player in players:
                name = player.get("name")
                if not name:
                    continue
                plus = player.get("plus", 0)
                minus = player.get("minus", 0)
                sum_points = player.get("sum", 0)
                if name not in player_stats:
                    player_stats[name] = {"games": 0, "total_plus": 0, "total_minus": 0, "total_sum": 0}
                player_stats[name]["games"] += 1
                player_stats[name]["total_plus"] += plus
                player_stats[name]["total_minus"] += minus
                player_stats[name]["total_sum"] += sum_points  # Исправлено: было "points", но инициализация использует "total_sum"

        # Добавляем игроков, которые есть в БД, но не участвовали в играх (с 0 баллами)
        for name in player_names:
            if name not in player_stats:
                player_stats[name] = {"games": 0, "total_plus": 0, "total_minus": 0, "total_sum": 0}

        # Формируем рейтинг и сортируем по total_sum (убыванию)
        rating = [
            {
                "name": name,
                "games": stats["games"],
                "total_plus": stats["total_plus"],
                "total_minus": stats["total_minus"],
                "points": stats["total_sum"],  # Оставлено как "points" для совместимости с фронтендом
                "club": clubs.get(name, None)  # Новое поле: клуб из User, None если не найден
            }
            for name, stats in player_stats.items()
        ]
        rating.sort(key=lambda x: x["points"], reverse=True)

        # Общее количество игроков
        total_count = len(rating)

        # Применяем пагинацию
        paginated_rating = rating[offset:offset + limit]

        # Возвращаем в формате, ожидаемом фронтендом
        return {"players": paginated_rating, "total_count": total_count}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения рейтинга: {str(e)}")
    finally:
        db.close()


@app.get("/getDetailedStats")
async def get_detailed_stats(
    limit: int = Query(10, description="Количество игроков на странице"),
    offset: int = Query(0, description="Смещение для пагинации игроков")
):
    db = SessionLocal()
    try:
        all_players = db.query(User).all()
        player_names = {p.nickname for p in all_players}
        clubs = {p.nickname: p.club for p in all_players}

        games = db.query(Game).all()

        player_stats = {}

        for game in games:
            game_data = json.loads(game.data)
            badge_color = game_data.get("badgeColor", "")
            players = game_data.get("players", [])

            for player in players:
                name = player.get("name")
                if not name:
                    continue
                role = player.get("role", "").lower()
                plus = player.get("plus", 0)
                minus = player.get("fouls", 0)
                sum_points = player.get("sum", 0)

                if name not in player_stats:
                    player_stats[name] = {
                        "totalPoints": 0,
                        "bonuses": 0,
                        "penalties": 0,
                        "wins": {"red": 0, "peaceful": 0, "mafia": 0, "don": 0, "sk": 0, "jk": 0},
                        "losses": {"red": 0, "peaceful": 0, "mafia": 0, "don": 0, "sk": 0, "jk": 0},
                        "wins_points": {"red": 0.0, "peaceful": 0.0, "mafia": 0.0, "don": 0.0, "sk": 0.0, "jk": 0.0},
                        "losses_points": {"red": 0.0, "peaceful": 0.0, "mafia": 0.0, "don": 0.0, "sk": 0.0, "jk": 0.0},
                        "gamesPlayed": {"peaceful": 0, "mafia": 0, "red": 0, "don": 0, "sk": 0, "jk": 0},
                        "wins_plus_list": {"peaceful": [], "mafia": [], "red": [], "don": [], "sk": [], "jk": []},
                        "losses_plus_list": {"peaceful": [], "mafia": [], "red": [], "don": [], "sk": [], "jk": []},
                        "role_plus": {"peaceful": [], "mafia": [], "red": [], "don": [], "sk": [], "jk": []}  # Оставлено для совместимости
                    }

                stats = player_stats[name]
                stats["totalPoints"] += sum_points
                stats["bonuses"] += plus
                stats["penalties"] += minus

                # Определяем выигрыш ли игрок по роли (зависит от badge_color)
                is_win = False
                if role == "мирный":
                    stats["gamesPlayed"]["peaceful"] += 1
                    stats["role_plus"]["peaceful"].append(plus)
                    if badge_color == "red":
                        is_win = True
                        stats["wins"]["peaceful"] += 1
                        stats["wins_points"]["peaceful"] += plus
                        stats["wins_plus_list"]["peaceful"].append(plus)
                    else:
                        stats["losses"]["peaceful"] += 1
                        stats["losses_points"]["peaceful"] += plus
                        stats["losses_plus_list"]["peaceful"].append(plus)

                elif role == "мафия":
                    stats["gamesPlayed"]["mafia"] += 1
                    stats["role_plus"]["mafia"].append(plus)
                    if badge_color == "black":
                        is_win = True
                        stats["wins"]["mafia"] += 1
                        stats["wins_points"]["mafia"] += plus
                        stats["wins_plus_list"]["mafia"].append(plus)
                    else:
                        stats["losses"]["mafia"] += 1
                        stats["losses_points"]["mafia"] += plus
                        stats["losses_plus_list"]["mafia"].append(plus)

                elif role == "шериф":
                    stats["gamesPlayed"]["red"] += 1
                    stats["role_plus"]["red"].append(plus)
                    if badge_color == "red":
                        is_win = True
                        stats["wins"]["red"] += 1
                        stats["wins_points"]["red"] += plus
                        stats["wins_plus_list"]["red"].append(plus)
                    else:
                        stats["losses"]["red"] += 1
                        stats["losses_points"]["red"] += plus
                        stats["losses_plus_list"]["red"].append(plus)

                elif role == "дон":
                    stats["gamesPlayed"]["don"] += 1
                    stats["role_plus"]["don"].append(plus)
                    if badge_color == "black":
                        is_win = True
                        stats["wins"]["don"] += 1
                        stats["wins_points"]["don"] += plus
                        stats["wins_plus_list"]["don"].append(plus)
                    else:
                        stats["losses"]["don"] += 1
                        stats["losses_points"]["don"] += plus
                        stats["losses_plus_list"]["don"].append(plus)

                elif role == "sk":
                    stats["gamesPlayed"]["sk"] += 1
                    stats["role_plus"]["sk"].append(plus)
                    if badge_color == "red":
                        is_win = True
                        stats["wins"]["sk"] += 1
                        stats["wins_points"]["sk"] += plus
                        stats["wins_plus_list"]["sk"].append(plus)
                    else:
                        stats["losses"]["sk"] += 1
                        stats["losses_points"]["sk"] += plus
                        stats["losses_plus_list"]["sk"].append(plus)

                elif role == "jk":
                    stats["gamesPlayed"]["jk"] += 1
                    stats["role_plus"]["jk"].append(plus)
                    if badge_color == "black":
                        is_win = True
                        stats["wins"]["jk"] += 1
                        stats["wins_points"]["jk"] += plus
                        stats["wins_plus_list"]["jk"].append(plus)
                    else:
                        stats["losses"]["jk"] += 1
                        stats["losses_points"]["jk"] += plus
                        stats["losses_plus_list"]["jk"].append(plus)

        # Добавляем игроков без игр
        for name in player_names:
            if name not in player_stats:
                player_stats[name] = {
                    "totalPoints": 0,
                    "bonuses": 0,
                    "penalties": 0,
                    "wins": {"red": 0, "peaceful": 0, "mafia": 0, "don": 0, "sk": 0, "jk": 0},
                    "losses": {"red": 0, "peaceful": 0, "mafia": 0, "don": 0, "sk": 0, "jk": 0},
                    "wins_points": {"red": 0.0, "peaceful": 0.0, "mafia": 0.0, "don": 0.0, "sk": 0.0, "jk": 0.0},
                    "losses_points": {"red": 0.0, "peaceful": 0.0, "mafia": 0.0, "don": 0.0, "sk": 0.0, "jk": 0.0},
                    "gamesPlayed": {"peaceful": 0, "mafia": 0, "red": 0, "don": 0, "sk": 0, "jk": 0},
                    "wins_plus_list": {"peaceful": [], "mafia": [], "red": [], "don": [], "sk": [], "jk": []},
                    "losses_plus_list": {"peaceful": [], "mafia": [], "red": [], "don": [], "sk": [], "jk": []},
                    "role_plus": {"peaceful": [], "mafia": [], "red": [], "don": [], "sk": [], "jk": []}
                }

        players_list = []
        for name, stats in player_stats.items():
            # Можно добавить вычисления мин/средних, если нужно
            players_list.append({
                "nickname": name,
                "club": clubs.get(name, None),
                **stats,
            })

        players_list.sort(key=lambda x: x["totalPoints"], reverse=True)

        total_count = len(players_list)
        paginated_players = players_list[offset:offset + limit]

        # Вычисление среднего балла по всем игрокам
        if total_count > 0:
            average_points = sum(p["totalPoints"] for p in players_list) / total_count
        else:
            average_points = 0

        return {
            "players": paginated_players,
            "total_count": total_count,
            "average_points": average_points
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка получения детальной статистики: {str(e)}")
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, workers=4)