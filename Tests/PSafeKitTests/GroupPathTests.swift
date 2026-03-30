import Testing
@testable import PSafeKit

struct GroupPathTests {
    @Test("GroupPath: New")
    func groupPathNew() {
        let path: GroupPath = "A"
        #expect(path.description == "A")
        let segments = path.getSegments()
        #expect(segments.count == 1)
        #expect(segments[0] == "A")
    }

    @Test("GroupPath: New (via components)")
    func groupPathNewViaComponents() {
        let path = GroupPath("A", "B")
        #expect(path.description == "A.B")
        let segments = path.getSegments()
        #expect(segments.count == 2)
        #expect(segments[0] == "A")
        #expect(segments[1] == "B")
    }

    @Test("GroupPath: New (via escaped components)")
    func groupPathNewViaEscapedComponents() {
        let path = GroupPath("A", "B.com")
        #expect(path.description == #"A.B\.com"#)

        let segments = path.getSegments()
        #expect(segments.count == 2)
        #expect(segments[0] == "A")
        #expect(segments[1] == "B.com")
    }

    @Test("GroupPath: New (null)")
    func groupPathNewNull() {
        let path = GroupPath(nil)
        #expect(path.description == "")

        let segments = path.getSegments()
        #expect(segments.count == 1)
        #expect(segments[0] == "")
    }

    @Test("GroupPath: Up")
    func groupPathUp() {
        let path: GroupPath = #"A.B.C\.d"#

        #expect(path.description == #"A.B.C\.d"#)
        #expect(path.up().description == "A.B")
        #expect(path.up().up().description == "A")
        #expect(path.up().up().up().description == "")
        #expect(path.up().up().up().up().description == "")
    }

    @Test("GroupPath: Append")
    func groupPathAppend() {
        let path: GroupPath = ""

        #expect(path.description == "")
        #expect(path.append(nil).description == "")
        #expect(path.append("").description == "")
        #expect(path.append("A").description == "A")
        #expect(path.append("A").append("B").description == "A.B")
        #expect(path.append("A").append("B").append("C.d").description == #"A.B.C\.d"#)
        #expect(path.append("A").append("B").append("").append("C.d").append("").description == #"A.B.C\.d"#)
    }

    @Test("GroupPath: Indexer Get")
    func groupPathIndexed() {
        let path: GroupPath = #"A.B.C\.d"#

        #expect(path[-1] == nil)
        #expect(path[0] == "A")
        #expect(path[1] == "B")
        #expect(path[2] == "C.d")
        #expect(path[3] == nil)
    }
}