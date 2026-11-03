package lab.bridge;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader and writer.
 *
 * The bridge deliberately has no dependencies. Adding Jackson to read one file would
 * mean a build that needs network access, a lockfile, and a supply chain, for the sake
 * of three documents that are already in the repository. This parser is about 200
 * lines and is covered by the bridge self-test.
 *
 * Supported: objects, arrays, strings with escapes, numbers, true, false, null.
 * Not supported (and rejected loudly): comments, trailing commas, NaN/Infinity.
 */
public final class Json {

    private Json() {
    }

    public static Object parse(String text) {
        Parser parser = new Parser(text);
        Object value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw new IllegalArgumentException("trailing content at offset " + parser.position());
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object value) {
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("expected an object, got " + describe(value));
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asArray(Object value) {
        if (!(value instanceof List)) {
            throw new IllegalArgumentException("expected an array, got " + describe(value));
        }
        return (List<Object>) value;
    }

    public static String asString(Object value) {
        if (!(value instanceof String)) {
            throw new IllegalArgumentException("expected a string, got " + describe(value));
        }
        return (String) value;
    }

    public static double asDouble(Object value) {
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        throw new IllegalArgumentException("expected a number, got " + describe(value));
    }

    public static List<String> asStringList(Object value) {
        List<String> out = new ArrayList<>();
        for (Object item : asArray(value)) {
            out.add(asString(item));
        }
        return out;
    }

    public static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Map) {
            return "object with " + ((Map<?, ?>) value).size() + " keys";
        }
        if (value instanceof List) {
            return "array of " + ((List<?>) value).size();
        }
        return value.getClass().getSimpleName();
    }

    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        writeValue(value, out);
        return out.toString();
    }

    private static void writeValue(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String) {
            writeString((String) value, out);
        } else if (value instanceof Boolean) {
            out.append(value.toString());
        } else if (value instanceof Double || value instanceof Float) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("cannot serialise a non-finite number");
            }
            if (d == Math.rint(d) && Math.abs(d) < 1e15) {
                out.append((long) d).append(".0");
            } else {
                out.append(d);
            }
        } else if (value instanceof Number) {
            out.append(value.toString());
        } else if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(String.valueOf(entry.getKey()), out);
                out.append(':');
                writeValue(entry.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof List) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeValue(item, out);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("cannot serialise " + value.getClass());
        }
    }

    private static void writeString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    public static Map<String, Object> ordered() {
        return new LinkedHashMap<>();
    }

    private static final class Parser {
        private final String text;
        private int index;

        Parser(String text) {
            this.text = text;
        }

        int position() {
            return index;
        }

        boolean atEnd() {
            return index >= text.length();
        }

        void skipWhitespace() {
            while (index < text.length()) {
                char c = text.charAt(index);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    index++;
                } else {
                    break;
                }
            }
        }

        Object parseValue() {
            skipWhitespace();
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of input");
            }
            char c = text.charAt(index);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> parseNumber();
            };
        }

        private Object parseLiteral(String literal, Object value) {
            if (!text.startsWith(literal, index)) {
                throw new IllegalArgumentException("invalid literal at offset " + index);
            }
            index += literal.length();
            return value;
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            index++; // consume {
            skipWhitespace();
            if (!atEnd() && text.charAt(index) == '}') {
                index++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (atEnd() || text.charAt(index) != '"') {
                    throw new IllegalArgumentException("expected an object key at offset " + index);
                }
                String key = parseString();
                skipWhitespace();
                if (atEnd() || text.charAt(index) != ':') {
                    throw new IllegalArgumentException("expected ':' after key at offset " + index);
                }
                index++;
                map.put(key, parseValue());
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated object");
                }
                char next = text.charAt(index);
                if (next == ',') {
                    index++;
                    continue;
                }
                if (next == '}') {
                    index++;
                    return map;
                }
                throw new IllegalArgumentException("expected ',' or '}' at offset " + index);
            }
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            index++; // consume [
            skipWhitespace();
            if (!atEnd() && text.charAt(index) == ']') {
                index++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated array");
                }
                char next = text.charAt(index);
                if (next == ',') {
                    index++;
                    continue;
                }
                if (next == ']') {
                    index++;
                    return list;
                }
                throw new IllegalArgumentException("expected ',' or ']' at offset " + index);
            }
        }

        private String parseString() {
            index++; // consume opening quote
            StringBuilder out = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated string");
                }
                char c = text.charAt(index++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (atEnd()) {
                    throw new IllegalArgumentException("dangling escape");
                }
                char esc = text.charAt(index++);
                switch (esc) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (index + 4 > text.length()) {
                            throw new IllegalArgumentException("truncated \\u escape");
                        }
                        out.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
                        index += 4;
                    }
                    default -> throw new IllegalArgumentException("invalid escape \\" + esc);
                }
            }
        }

        private Object parseNumber() {
            int start = index;
            if (!atEnd() && (text.charAt(index) == '-' || text.charAt(index) == '+')) {
                index++;
            }
            boolean seenDot = false;
            while (!atEnd()) {
                char c = text.charAt(index);
                if (c >= '0' && c <= '9') {
                    index++;
                } else if (c == '.' && !seenDot) {
                    seenDot = true;
                    index++;
                } else if (c == 'e' || c == 'E') {
                    index++;
                    if (!atEnd() && (text.charAt(index) == '-' || text.charAt(index) == '+')) {
                        index++;
                    }
                } else {
                    break;
                }
            }
            String slice = text.substring(start, index);
            if (slice.isEmpty() || slice.equals("-")) {
                throw new IllegalArgumentException("invalid number at offset " + start);
            }
            return Double.valueOf(slice);
        }
    }
}
