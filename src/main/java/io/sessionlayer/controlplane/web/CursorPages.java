package io.sessionlayer.controlplane.web;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.data.domain.Sort;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Cursor (keyset) pagination for the management collections (FR-API-1).
 * Ordering is by the entity's UUIDv7 {@code id}, which is time-ordered, so a
 * page is stable under concurrent inserts (no OFFSET drift): the next page
 * starts strictly after the last id. The cursor is an opaque base64url of that
 * id; an unparseable cursor is a {@code 400}. One extra row is fetched to
 * decide whether a {@code nextCursor} exists.
 */
@Component
public class CursorPages {

	public static final int DEFAULT_LIMIT = 50;
	public static final int MAX_LIMIT = 200;

	private final R2dbcEntityTemplate template;

	public CursorPages(R2dbcEntityTemplate template) {
		this.template = template;
	}

	public record Page<T>(List<T> items, String nextCursor) {
	}

	public <T> Mono<Page<T>> page(Class<T> type, Criteria criteria, String cursor, Integer limit,
			Function<T, UUID> idOf) {
		int pageSize = clamp(limit);
		UUID after = decodeCursor(cursor);
		Criteria effective = criteria == null ? Criteria.empty() : criteria;
		if (after != null) {
			effective = effective.and("id").greaterThan(after);
		}
		Query query = Query.query(effective).sort(Sort.by(Sort.Direction.ASC, "id")).limit(pageSize + 1);
		return template.select(type).matching(query).all().collectList().map(rows -> {
			boolean more = rows.size() > pageSize;
			List<T> items = more ? new ArrayList<>(rows.subList(0, pageSize)) : rows;
			String next = more ? encodeCursor(idOf.apply(items.get(items.size() - 1))) : null;
			return new Page<>(items, next);
		});
	}

	public static int clamp(Integer limit) {
		if (limit == null) {
			return DEFAULT_LIMIT;
		}
		return Math.max(1, Math.min(MAX_LIMIT, limit));
	}

	public static UUID decodeCursor(String cursor) {
		if (cursor == null || cursor.isBlank()) {
			return null;
		}
		try {
			return UUID.fromString(new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8));
		} catch (IllegalArgumentException bad) {
			throw ApiProblemException.malformed("invalid pagination cursor");
		}
	}

	public static String encodeCursor(UUID id) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(id.toString().getBytes(StandardCharsets.UTF_8));
	}
}
