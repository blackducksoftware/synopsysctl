package testutils

import (
	"fmt"
	"math/rand"
	"time"
)

// CreateUniqueID ...
func CreateUniqueID() string {
	t := time.Now()
	return fmt.Sprintf("%d%d%d%d%d%d", t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second())
}

// CreateUniqueNamespace ...
func CreateUniqueNamespace(prefix string) string {
	if prefix == "" {
		prefix = "ns"
	}
	return fmt.Sprintf("%s-%s", prefix, CreateUniqueID())
}

// GenName ...
func GenName(appName string) string {
	rand.Seed(time.Now().UTC().UnixNano())
	adjectives := []string{"absolute", "accepted", "ace", "active", "actual", "adapted", "adapting", "adequate", "adjusted", "advanced", "alive", "amazed", "amazing", "ample", "amused", "amusing", "artistic", "awake", "aware", "balanced", "beloved", "better", "big", "blessed", "bold", "boss", "brave", "bright", "bursting", "busy", "calm", "capable", "careful", "caring", "casual", "champion", "charmed", "charming", "cheerful", "chief", "choice", "civil", "classic", "clean", "clever", "climbing", "coherent", "comic", "communal", "complete", "composed", "concise", "concrete", "content", "cool", "correct", "cosmic", "crack", "creative", "credible", "crisp", "crucial", "cuddly", "cunning", "curious", "cute", "daring", "darling", "dashing", "decent", "deep", "definite", "delicate", "desired", "destined", "devoted", "discrete", "distinct", "diverse", "divine", "dominant", "driven", "driving", "dynamic", "eager", "easy", "electric", "elegant", "emerging", "eminent", "enabled", "enabling", "endless", "engaged", "engaging", "enhanced", "enjoyed", "enormous", "epic", "equipped", "eternal", "ethical", "evident", "evolved", "evolving", "exact", "excited", "exciting", "exotic", "expert", "factual", "fair", "faithful", "famous", "fancy", "fast", "feasible", "fine", "finer", "firm", "first", "fit", "fitting", "fleet", "flexible", "flowing", "fluent", "flying", "fond", "frank", "free", "fresh", "full", "fun", "funky", "funny", "game", "generous", "gentle", "genuine", "giving", "glad", "glorious", "glowing", "golden", "good", "gorgeous", "grand", "grateful", "great", "growing", "grown", "guided", "guiding", "handy", "happy", "hardy", "harmless", "healthy", "helped", "helpful", "helping", "heroic", "hip", "holy", "honest", "hopeful", "hot", "huge", "humane", "humble", "humorous", "ideal", "immense", "immortal", "immune", "improved", "infinite", "informed", "innocent", "inspired", "integral", "intense", "intimate", "inviting", "joint", "just", "keen", "key", "kind", "knowing", "large", "lasting", "leading", "learning", "legal", "legible", "lenient", "liberal", "light", "likable", "literate", "lively", "living", "logical", "loved", "loving", "loyal", "lucky", "magical", "magnetic", "main", "major", "massive", "master", "mature", "merry", "mighty", "minty", "modern", "modest", "moral", "musical", "national", "natural", "nearby", "neat", "neutral", "nice", "noble", "normal", "notable", "novel", "obliging", "open", "optimal", "optimum", "organic", "oriented", "outgoing", "patient", "peaceful", "perfect", "pet", "pleasant", "pleased", "pleasing", "poetic", "polished", "polite", "popular", "positive", "possible", "powerful", "precious", "precise", "premium", "prepared", "present", "pretty", "primary", "prime", "pro", "probable", "profound", "promoted", "prompt", "proper", "proud", "proven", "pumped", "pure", "quality", "quick", "quiet", "rapid", "rare", "rational", "real", "refined", "regular", "relaxed", "relaxing", "relevant", "relieved", "renewed", "resolved", "rested", "rich", "robust", "romantic", "ruling", "sacred", "safe", "saved", "saving", "secure", "select", "selected", "sensible", "settled", "settling", "sharing", "sharp", "shining", "simple", "sincere", "singular", "skilled", "smart", "smashing", "smiling", "smooth", "sneaky", "social", "solid", "special", "spectacular", "splendid", "square", "stable", "star", "sterling", "striking", "strong", "stunning", "subtle", "suitable", "suited", "sunny", "super", "superb", "supreme", "sweet", "talented", "teaching", "tender", "thankful", "the-chosen", "thorough", "tidy", "tight", "tolerant", "top", "topical", "touching", "tough", "true", "trusted", "trusting", "trusty", "typical", "quick", "ultimate", "unbiased", "uncommon", "unique", "upright", "upward", "usable", "useful", "valid", "valued", "viable", "vital", "vocal", "wanted", "warm", "wealthy", "welcome", "welcomed", "whole", "willing", "winning", "wired", "wise", "witty", "wondrous", "working", "worthy"}
	adj := adjectives[rand.Intn(len(adjectives))]
	return fmt.Sprintf("%s-%s", adj, appName)
}
