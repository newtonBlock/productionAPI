import time
from app.cache import ResponseCache

cache = ResponseCache(ttl_seconds=3)

result = cache.get('What is Python?')
print(f'1. First lookup: {result} (miss - nothing cached yet)')

cache.set('What is Python?', 'Python is a programming language.')
print(f'2. Stored response in cache')

result = cache.get('What is Python?')
print(f'3. Second lookup: {result} (HIT!)')

result = cache.get('what is python?')
print(f'4. Lowercase lookup: {result} (HIT - case insensitive!)')

result = cache.get('What is javascript?')
print(f'5. Diffe: {result} (miss)')

print(f'6. Stats: {cache.stats}')

print(f'7. Waiting 4 seconds for TTL expiration...')
time.sleep(4)

result = cache.get('What is Python?')
print(f'8. After TTL: {result} (miss - expired!)')
print(f'9. Final Stats: {cache.stats}')

