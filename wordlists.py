"""Embedded word lists used for blocklist and dictionary checks.

Both lists are lowercase. Order matters: earlier entries are treated as more
likely guesses (lower rank = fewer bits of entropy).
"""

# Most common leaked passwords, roughly ordered by popularity.
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567", "111111", "123123", "abc123", "1234567890", "password1",
    "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon",
    "sunshine", "princess", "letmein", "654321", "monkey", "1qaz2wsx",
    "123321", "qwertyuiop", "superman", "asdfghjkl", "trustno1", "welcome",
    "admin", "football", "baseball", "master", "shadow", "michael",
    "jennifer", "666666", "121212", "7777777", "987654321", "1234",
    "charlie", "donald", "loveme", "access", "starwars", "batman",
    "whatever", "freedom", "hello", "ninja", "mustang", "qazwsx", "123qwe",
    "killer", "jordan23", "harley", "ranger", "hockey", "soccer", "pepper",
    "daniel", "andrew", "thomas", "joshua", "ashley", "bailey", "buster",
    "cheese", "computer", "secret", "summer", "flower", "cookie",
    "chocolate", "maggie", "liverpool", "samsung", "google", "login",
    "pokemon", "minecraft", "zxcvbnm", "asdf1234", "1111", "aaaaaa",
    "abcdef", "changeme", "default", "guest", "root", "test", "test123",
    "admin123", "welcome1", "password123", "iloveyou1", "lovely", "159753",
    "147258369", "112233", "hunter2", "qwe123", "abcd1234", "11111111",
    "88888888", "passpass", "letmein1", "princess1", "sunshine1",
]

# Common English words, names, and themes people build passwords from.
COMMON_WORDS = [
    "love", "baby", "angel", "family", "forever", "happy", "friend",
    "money", "music", "dance", "magic", "power", "silver", "golden",
    "orange", "purple", "yellow", "black", "white", "green", "blue", "red",
    "tiger", "eagle", "lion", "wolf", "bear", "horse", "puppy", "kitty",
    "monster", "rocket", "pirate", "knight", "wizard", "legend", "hero",
    "star", "moon", "earth", "water", "fire", "storm", "thunder", "winter",
    "spring", "autumn", "rose", "cherry", "apple", "banana", "mango",
    "pizza", "coffee", "candy", "sugar", "honey", "sweet", "tennis", "golf",
    "player", "gamer", "games", "hunter", "shooter", "sniper", "user",
    "system", "server", "network", "internet", "office", "school",
    "college", "student", "teacher", "doctor", "nurse", "police", "army",
    "navy", "jesus", "christ", "faith", "grace", "blessed", "heaven",
    "hell", "devil", "demon", "ghost", "dark", "light", "night", "dream",
    "heart", "soul", "life", "live", "death", "world", "peace", "liberty",
    "america", "london", "paris", "berlin", "india", "china", "canada",
    "texas", "york", "boston", "chicago", "john", "james", "robert",
    "william", "david", "richard", "joseph", "charles", "matthew",
    "anthony", "mark", "paul", "steven", "kevin", "brian", "george",
    "edward", "mary", "patricia", "linda", "elizabeth", "barbara", "susan",
    "jessica", "sarah", "karen", "nancy", "lisa", "betty", "emma",
    "olivia", "sophia", "buddy", "bella", "lucy", "daisy", "luna", "rocky",
    "king", "queen", "prince", "lady", "boss", "chief", "captain", "super",
    "mega", "ultra", "cool", "crazy", "funny", "lucky", "pretty", "sexy",
    "smile", "thank", "please", "sorry", "never", "always", "maybe",
    "change", "trust", "chicken", "turtle", "spider", "shark", "snake",
    "falcon", "phoenix", "cobra", "viper", "raven", "matrix", "zombie",
    "alien", "robot", "cyber", "hacker", "code", "pass", "word", "lock",
    "safe", "home", "house", "garden", "beach", "ocean", "river",
    "mountain", "forest", "island", "rainbow", "diamond", "crystal", "gold",
    "cash", "dollar", "rich", "winner", "champion", "victory", "number",
    "three", "four", "five", "seven", "nine", "zero", "first", "best",
    "true", "yankees", "cowboys", "lakers", "arsenal", "chelsea",
    "barcelona", "madrid", "united", "juventus", "ferrari", "porsche",
    "mercedes", "honda", "toyota", "naruto", "spiderman", "mickey",
    "disney", "marvel", "fortnite", "roblox", "iphone", "windows",
]
